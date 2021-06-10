/*
 * Copyright (c) 2013 CINECA (www.hpc.cineca.it)
 *
 * Copyright (c) 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * Globus DSI to manage data on iRODS.
 *
 * Author: Roberto Mucci - SCAI - CINECA
 * Email:  hpc-service@cineca.it
 *
 */

//#pragma GCC diagnostic ignored "-Wregister"`
extern "C" {
  #include "globus_gridftp_server.h"
}
//#pragma GCC diagnostic pop

#ifdef IRODS_HEADER_HPP
  #include "rodsClient.hpp"
#else
  #include "rodsClient.h"
#endif

#include "irods_query.hpp"
#include "irods_string_tokenize.hpp"
#include "irods_virtual_path.hpp"
#include "irods_hasher_factory.hpp"
#ifdef IRODS_HEADER_HPP
  #include "rodsClient.hpp"
#else
  #include "rodsClient.h"
#endif

#include <base64.h>

// boost includes
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <string>

#include "pid_manager.h"
#include <cstring>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <iomanip>

#define MAX_DATA_SIZE 1024

/* Path to the file mapping iRODS path and resources*/
#define IRODS_RESOURCE_MAP "irodsResourceMap"

#define IRODS_USER_MAP "irodsUerap"

#define IRODS_LIST_UPDATE_INTERVAL_SECONDS             10
#define IRODS_LIST_UPDATE_INTERVAL_COUNT               1000
#define IRODS_CHECKSUM_DEFAULT_UPDATE_INTERVAL_SECONDS 5

#ifndef DEFAULT_HOMEDIR_PATTERN
  /* Default homeDir pattern, referencing up to two strings with %s.
   * If used, first gets substituted with the zone name, second with the user name.
   */
  #define DEFAULT_HOMEDIR_PATTERN "/%s/home/%s"
#endif

/* name of environment variable to check for the homeDirPattern */
#define HOMEDIR_PATTERN "homeDirPattern"

/* if present, connect as the admin account stored in rodsEnv and not as the user */
#define IRODS_CONNECT_AS_ADMIN "irodsConnectAsAdmin"

/* If present, use the handle server to resolve PID */
#define PID_HANDLE_SERVER "pidHandleServer"

const static std::string CHECKSUM_AVU_NAMESPACE{"GLOBUS"};

static int                              iRODS_l_dev_wrapper = 10;
/* structure and global variable for holding pointer to the (last) selected resource mapping */
struct iRODS_Resource
{
      char * path;
      char * resource;
};

struct iRODS_Resource iRODS_Resource_struct = {nullptr,NULL};

typedef struct cksum_thread_args
{
    bool                    *done_flag;
    globus_gfs_operation_t  *op;
    pthread_mutex_t         *mutex;
    int                     *update_interval;
    size_t                  *bytes_processed;
} cksum_thread_args_t;

GlobusDebugDefine(GLOBUS_GRIDFTP_SERVER_IRODS);
static
globus_version_t local_version =
{
    0, /* major version number */
    1, /* minor version number */
    1369393102,
    0 /* branch ID */
};

int convert_base64_to_hex_string(const std::string& base64_str, const int& bit_count, std::string& out_str) {

    unsigned char out[bit_count / 8];
    unsigned long out_len = bit_count / 8;

    int ret = base64_decode(reinterpret_cast<const unsigned char*>(base64_str.c_str()), base64_str.size(), out, &out_len);

    if (ret < 0) {
        return ret;
    } else {

        std::stringstream ss;

        for (unsigned long offset = 0; offset < out_len; offset += 1) {
            unsigned char *current_byte = reinterpret_cast<unsigned char*>(out + offset);
            int int_value = *current_byte;
            ss << std::setfill('0') << std::setw(2) << std::hex << int_value;
        }
        out_str = ss.str();
    }
    return 0;
}

int
iRODS_l_reduce_path(
    char *                              path)
{
    char *                              ptr;
    int                                 len;
    int                                 end;

    len = strlen(path);

    while(len > 1 && path[len-1] == '/')
    {
        len--;
        path[len] = '\0';
    }
    end = len-2;
    while(end >= 0)
    {
        ptr = &path[end];
        if(strncmp(ptr, "//", 2) == 0)
        {
            memmove(ptr, &ptr[1], len - end);
            len--;
        }
        end--;
    }
    return 0;
}

typedef struct globus_l_iRODS_read_ahead_s
{
    struct globus_l_gfs_iRODS_handle_s *  iRODS_handle;
    globus_off_t                        offset;
    globus_size_t                       length;
    globus_byte_t *                     buffer;
} globus_l_iRODS_read_ahead_t;

static
int
iRODS_l_filename_hash(
    char *                              string)
{
    int                                 rc;
    unsigned long                       h = 0;
    unsigned long                       g;
    char *                              key;

    if(string == nullptr)
    {
        return 0;
    }

    key = (char *) string;

    while(*key)
    {
        h = (h << 4) + *key++;
        if((g = (h & 0xF0UL)))
        {
            h ^= g >> 24;
            h ^= g;
        }
    }

    rc = h % 2147483647;
    return rc;
}

char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep
    int len_with; // length of with
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    if (!orig)
    {
        return nullptr;
    }
    if (!rep)
    {
        rep = const_cast<char*>("");
    }
    len_rep = strlen(rep);
    if (!with)
    {
        with = const_cast<char*>("");
    }
    len_with = strlen(with);

    ins = orig;
    for ((count = 0); (tmp = strstr(ins, rep)); ++count)
    {
        ins = tmp + len_rep;
    }

    tmp = result = static_cast<char*>(malloc(strlen(orig) + (len_with - len_rep) * count + 1));

    if (!result)
    {
        return nullptr;
    }

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

static
void
iRODS_disconnect(
    rcComm_t *                           conn)

{
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: disconnected.\n");
    rcDisconnect(conn);
}

static
char *
iRODS_getUserName(
    char *                              DN)
{
    char *DN_Read = nullptr;
    char *iRODS_user_name = nullptr;
    char *search = const_cast<char*>(";");

    FILE *file = fopen (getenv(IRODS_USER_MAP), "r" );
    if ( file != nullptr )
    {
        char line [ 256 ]; /* or other suitable maximum line size */
        while ( fgets ( line, sizeof line, file ) != nullptr ) /* read a line */
        {
            // Token will point to the part before the ;.
            DN_Read = strtok(line, search);
            if ( strcmp(DN, DN_Read) == 0)
            {
                iRODS_user_name = strtok(nullptr, search);
                unsigned int len = strlen(iRODS_user_name);
                if (iRODS_user_name[len - 1] == '\n')
                {
                    iRODS_user_name[len - 1] = '\0'; //Remove EOF
                }
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: User found in irodsUserMap.conf: DN = %s, iRODS user = %s.\n", DN, iRODS_user_name);
                break;
            }
        }
        fclose ( file );
    }
    // the username is a string on the stack, return a copy (if it's not nullptr)
    return iRODS_user_name == nullptr ? NULL : strdup(iRODS_user_name);
}

static
void
iRODS_getResource(
    char *                         destinationPath)
{
    char *path_Read = nullptr;
    char *iRODS_res = nullptr;
    char *search = const_cast<char*>(";");

    FILE *file = fopen (getenv(IRODS_RESOURCE_MAP), "r" );
    if ( file != nullptr )
    {
        char line [ 256 ]; /* or other suitable maximum line size */
        while ( fgets ( line, sizeof line, file ) != nullptr ) /* read a line */
        {
            // Token will point to the part before the ;.
            path_Read = strtok(line, search);

            if (strncmp(path_Read, destinationPath, strlen(path_Read)) == 0)
            {
                    //found the resource
                iRODS_res = strtok(nullptr, search);
                unsigned int len = strlen(iRODS_res);
                if (iRODS_res[len - 1] == '\n')
                {
                    iRODS_res[len - 1] = '\0'; //Remove EOF
                }
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: found iRODS resource  %s for destinationPath %s.\n", iRODS_res, destinationPath);

                /* store the mapping in the global pointers in iRODS_Resource_struct - duplicating the string value.
                 * Free any previously stored (duplicated) string pointer first!
                 */
                if (iRODS_Resource_struct.resource != nullptr) { free(iRODS_Resource_struct.resource); };
                iRODS_Resource_struct.resource =  strdup(iRODS_res);
                if (iRODS_Resource_struct.path != nullptr) { free(iRODS_Resource_struct.path); };
                iRODS_Resource_struct.path = strdup(path_Read);
                break;
            }
        }
        fclose ( file );
    }
    else
    {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: irodsResourceMap file not found: %s.\n", getenv(IRODS_RESOURCE_MAP));
    }

}

static
int
iRODS_l_stat1(
    rcComm_t *                          conn,
    globus_gfs_stat_t *                 stat_out,
    char *                              start_dir)
{
    int                                 status;
    char *                              tmp_s;
    char *                              rsrcName;
    char *                              fname;

    collHandle_t collHandle;
    int queryFlags;
    queryFlags = DATA_QUERY_FIRST_FG | VERY_LONG_METADATA_FG | NO_TRIM_REPL_FG;
    status = rclOpenCollection (conn, start_dir, queryFlags,  &collHandle);
    if (status >= 0)
    {

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: found collection %s.\n", start_dir);
        rsrcName = (char*) start_dir;
        memset(stat_out, '\0', sizeof(globus_gfs_stat_t));
        fname = rsrcName ? rsrcName : const_cast<char*>("(null)");
        tmp_s = strrchr(fname, '/');
        if(tmp_s != nullptr) fname = tmp_s + 1;
        stat_out->ino = iRODS_l_filename_hash(rsrcName);
        stat_out->name = strdup(fname);
        stat_out->nlink = 0;
        stat_out->uid = getuid();
        stat_out->gid = getgid();
        stat_out->size = 0;
        stat_out->dev = iRODS_l_dev_wrapper++;
        stat_out->mode =
            S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR |
            S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;
    }
    else
    {
        dataObjInp_t dataObjInp;
        rodsObjStat_t *rodsObjStatOut = nullptr;
        bzero (&dataObjInp, sizeof (dataObjInp));
        rstrcpy (dataObjInp.objPath, start_dir, MAX_NAME_LEN);
        status = rcObjStat (conn, &dataObjInp, &rodsObjStatOut);
        if (status >= 0)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: found data object %s.\n", start_dir);
            memset(stat_out, '\0', sizeof(globus_gfs_stat_t));
            stat_out->symlink_target = nullptr;
            stat_out->name = strdup(start_dir);
            stat_out->nlink = 0;
            stat_out->uid = getuid();
            stat_out->gid = getgid();
            stat_out->size = rodsObjStatOut->objSize;

            time_t realTime = atol(rodsObjStatOut->modifyTime);
            stat_out->ctime = realTime;
            stat_out->mtime = realTime;
            stat_out->atime = realTime;
            stat_out->dev = iRODS_l_dev_wrapper++;
            stat_out->ino = iRODS_l_filename_hash(start_dir);
            stat_out->mode = S_IFREG | S_IRUSR | S_IWUSR |
                S_IXUSR | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;
        }
        freeRodsObjStat (rodsObjStatOut);
    }

    return status;
}

static
int
iRODS_l_stat_dir(
    globus_gfs_operation_t              op,
    rcComm_t*                           conn,
    globus_gfs_stat_t **                out_stat,
    int *                               out_count,
    char *                              start_dir,
    char *                              username)
{
    int                                 status;
    char *                              tmp_s;
    globus_gfs_stat_t *                 stat_array = nullptr;
    int                                 stat_count = 0;
    int                                 stat_ndx = 0;

    collHandle_t collHandle;
    collEnt_t collEnt;
    int queryFlags;
    int internal_idx;

    char *                              stat_last_data_obj_name = nullptr;
    // will hold a copy of the pointer to last file, not a copy of the string

    queryFlags = DATA_QUERY_FIRST_FG | VERY_LONG_METADATA_FG | NO_TRIM_REPL_FG;
    status = rclOpenCollection (conn, start_dir, queryFlags,  &collHandle);

    if (status < 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: rclOpenCollection of %s error. status = %d", start_dir, status);
        return status;
    }

    time_t last_update_time = time(0);

    //We should always be including "." and ".."
    //Run this block twice, add "." on iteration 0, ".." on iteration 1
    //We skip this for the root directory, as it already provides "."
    //internally - and we do not need .. there.
    if (strcmp("/", start_dir) !=0 ) {
        for (internal_idx = 0; internal_idx<=1; internal_idx++) {
            stat_count++;
            stat_array = (globus_gfs_stat_t *) globus_realloc(stat_array, stat_count * sizeof(globus_gfs_stat_t));
            memset(&stat_array[stat_ndx], '\0', sizeof(globus_gfs_stat_t));
            if ( internal_idx == 0 ) {
                stat_array[stat_ndx].ino = iRODS_l_filename_hash(start_dir);
                stat_array[stat_ndx].name = globus_libc_strdup(".");
            } else {
                char * parent_dir = strdup(start_dir);
                char * last_slash = strrchr(parent_dir,'/');
                if (last_slash != nullptr) *last_slash='\0';
                stat_array[stat_ndx].ino = iRODS_l_filename_hash(parent_dir);
                stat_array[stat_ndx].name = globus_libc_strdup("..");
                free(parent_dir);
            };
            stat_array[stat_ndx].nlink = 0;
            stat_array[stat_ndx].uid = getuid();
            stat_array[stat_ndx].gid = getgid();
            stat_array[stat_ndx].size = 0;
            stat_array[stat_ndx].dev = iRODS_l_dev_wrapper++;
            stat_array[stat_ndx].mode = S_IFDIR | S_IRUSR | S_IWUSR |
                S_IXUSR | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;
            stat_ndx++;

        }
    }

    while ((status = rclReadCollection (conn, &collHandle, &collEnt)) >= 0)
    {

        // skip duplicate listings of data objects (additional replicas)
        if ( (collEnt.objType == DATA_OBJ_T) &&
             (stat_last_data_obj_name != nullptr) &&
             (strcmp(stat_last_data_obj_name, collEnt.dataName) == 0) ) continue;

        stat_count++;
        stat_array = (globus_gfs_stat_t *) globus_realloc(stat_array, stat_count * sizeof(globus_gfs_stat_t));

        if (collEnt.objType == DATA_OBJ_T)
        {
            memset(&stat_array[stat_ndx], '\0', sizeof(globus_gfs_stat_t));
            stat_array[stat_ndx].symlink_target = nullptr;
            stat_array[stat_ndx].name = globus_libc_strdup(collEnt.dataName);
            stat_last_data_obj_name = stat_array[stat_ndx].name;
            stat_array[stat_ndx].nlink = 0;
            stat_array[stat_ndx].uid = getuid();

            //I could get unix uid from iRODS owner, but iRODS owner can not exist as unix user
            //so now the file owner is always the user who started the gridftp process
            //stat_array[stat_ndx].uid = getpwnam(ownerName)->pw_uid;

            stat_array[stat_ndx].gid = getgid();
            stat_array[stat_ndx].size = collEnt.dataSize;

            time_t realTime = atol(collEnt.modifyTime);
            stat_array[stat_ndx].ctime = realTime;
            stat_array[stat_ndx].mtime = realTime;
            stat_array[stat_ndx].atime = realTime;
            stat_array[stat_ndx].dev = iRODS_l_dev_wrapper++;
            stat_array[stat_ndx].ino = iRODS_l_filename_hash(collEnt.dataName);
            stat_array[stat_ndx].mode = S_IFREG | S_IRUSR | S_IWUSR |
                S_IXUSR | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;

        }
        else
        {
            char * fname;
            fname = collEnt.collName ? collEnt.collName : const_cast<char*>("(null)");
            tmp_s = strrchr(fname, '/');
            if(tmp_s != nullptr) fname = tmp_s + 1;
            if(strlen(fname) == 0)
            {
                //in iRODS empty dir collection is root dir
                fname = const_cast<char*>(".");
            }

            memset(&stat_array[stat_ndx], '\0', sizeof(globus_gfs_stat_t));
            stat_array[stat_ndx].ino = iRODS_l_filename_hash(collEnt.collName);
            stat_array[stat_ndx].name = strdup(fname);
            stat_array[stat_ndx].nlink = 0;
            stat_array[stat_ndx].uid = getuid();
            stat_array[stat_ndx].gid = getgid();
            stat_array[stat_ndx].size = 0;

            time_t realTime = atol(collEnt.modifyTime);
            stat_array[stat_ndx].ctime = realTime;
            stat_array[stat_ndx].mtime = realTime;

            stat_array[stat_ndx].dev = iRODS_l_dev_wrapper++;
            stat_array[stat_ndx].mode = S_IFDIR | S_IRUSR | S_IWUSR |
                S_IXUSR | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;
        }

        stat_ndx++;

        // go ahead and send a partial listing if either time or count has expired
        time_t now = time(0);
        time_t diff = now - last_update_time;

        if (diff >= IRODS_LIST_UPDATE_INTERVAL_SECONDS || stat_count >= IRODS_LIST_UPDATE_INTERVAL_COUNT) {

            // send partial stat
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: calling globus_gridftp_server_finished_stat_partial\n");
            globus_gridftp_server_finished_stat_partial(op, GLOBUS_SUCCESS, stat_array, stat_count);

            // free the names and array
            for(int i = 0; i < stat_count; i++)
            {
                globus_free(stat_array[i].name);
            }
            globus_free(stat_array);
            stat_array = nullptr;
            stat_count = 0;
            stat_ndx = 0;

            last_update_time = now;
        }
    }

    rclCloseCollection (&collHandle);

    *out_stat = stat_array;
    *out_count = stat_count;

    if (status < 0 && status != -808000) {
        return (status);
    } else {
        return (0);
    }
}

/*
*  the data structure representing the FTP session
*/
typedef struct globus_l_gfs_iRODS_handle_s
{
    rcComm_t *                          conn;
    int                                 stor_sys_type;
    int                                 fd;
    globus_mutex_t                      mutex;
    globus_gfs_operation_t              op;
    globus_bool_t                       done;
    globus_bool_t                       read_eof;
    int                                 outstanding;
    int                                 optimal_count;
    globus_size_t                       block_size;
    globus_result_t                     cached_res;
    globus_off_t                        blk_length;
    globus_off_t                        blk_offset;

    globus_fifo_t                       rh_q;

    char *                              hostname;
    int                                 port;

    char *                              zone;
    char *                              defResource;
    char *                              user;
    char *                              domain;

    char *                              irods_dn;
    char *                              original_stat_path;
    char *                              resolved_stat_path;

} globus_l_gfs_iRODS_handle_t;

static
globus_bool_t
globus_l_gfs_iRODS_read_from_net(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle);

static
globus_bool_t
globus_l_gfs_iRODS_send_next_to_client(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle);

static
void
globus_l_gfs_iRODS_read_ahead_next(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle);

/*
 *  utility function to make errors
 */
static
globus_result_t
globus_l_gfs_iRODS_make_error(
    const char *                        msg,
    int                                 status)
{
    char *errorSubName;
    const char *errorName;
    char *                              err_str;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_iRODS_make_error);

    errorName = rodsErrorName(status, &errorSubName);

    err_str = globus_common_create_string("iRODS DSI. Error: %s. %s: %s, status: %d.\n", msg, errorName, errorSubName, status);
    result = GlobusGFSErrorGeneric(err_str);
    free(err_str);

    return result;
}

/*************************************************************************
 *  start
 *  -----
 *  This function is called when a new session is initialized, ie a user
 *  connectes to the server.  This hook gives the dsi an oppertunity to
 *  set internal state that will be threaded through to all other
 *  function calls associated with this session.  And an oppertunity to
 *  reject the user.
 *
 *  finished_info.info.session.session_arg should be set to an DSI
 *  defined data structure.  This pointer will be passed as the void *
 *  user_arg parameter to all other interface functions.
 *
 *  NOTE: at nice wrapper function should exist that hides the details
 *        of the finished_info structure, but it currently does not.
 *        The DSI developer should jsut follow this template for now
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: %s called\n", __FUNCTION__);

    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    globus_result_t                           result;
    globus_gfs_finished_info_t          finished_info;

    GlobusGFSName(globus_l_gfs_iRODS_start);

    rodsEnv myRodsEnv;
    char *user_name;
    char *homeDirPattern;
    int status;
    rErrMsg_t errMsg;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *)
        globus_malloc(sizeof(globus_l_gfs_iRODS_handle_t));

    if(iRODS_handle == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS DSI start: malloc failed");
        goto error;
    }
    globus_mutex_init(&iRODS_handle->mutex, nullptr);
    globus_fifo_init(&iRODS_handle->rh_q);

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = iRODS_handle;
    finished_info.info.session.username = session_info->username;

    status = getRodsEnv(&myRodsEnv);
    if (status >= 0) {

        // myRodsEnv is a structure on the stack, we must make explicit string copies
        iRODS_handle->hostname = strdup(myRodsEnv.rodsHost);
        iRODS_handle->port = myRodsEnv.rodsPort;
        iRODS_handle->zone = strdup(myRodsEnv.rodsZone);
        // copy also the default resource if it is set
        if (strlen(myRodsEnv.rodsDefResource) > 0 ) {
            iRODS_handle->defResource = strdup(myRodsEnv.rodsDefResource);
        } else {
            iRODS_handle->defResource = nullptr;
        }
        iRODS_handle->user = iRODS_getUserName(session_info->subject); //iRODS usernmae
        user_name = strdup(session_info->username); //Globus user name

        if (iRODS_handle->user == nullptr)
        {
            iRODS_handle->user = strdup(session_info->username);
        }
        iRODS_handle->original_stat_path = nullptr;
        iRODS_handle->resolved_stat_path = nullptr;

        //Get zone from username if it contains "#"
        char delims[] = "#";
        char *token = nullptr;
        // strtok modifies the input string, so we instead pass it a copy
        char *username_to_parse = strdup(iRODS_handle->user);
        token = strtok( username_to_parse, delims );
        if (token != nullptr ) {
            // Second token is the zone
            char *token2 = strtok( nullptr, delims );
            if ( token2 != nullptr ) {
                if (iRODS_handle->zone != nullptr) free(iRODS_handle->zone);
                iRODS_handle->zone = strdup(token2);
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: found zone '%s' in user name '%s'\n", iRODS_handle->zone, iRODS_handle->user);
                if (iRODS_handle->user != nullptr) free(iRODS_handle->user);
                iRODS_handle->user = strdup(token);
            }
        }
        free(username_to_parse);

        if (getenv(IRODS_CONNECT_AS_ADMIN)!=nullptr) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS_handle->hostname = [%s] iRODS_handle->port = [%i] myRodsEnv.rodsUserName = [%s] myRodsEnv.rodsZone = [%s] iRODS_handle->user = [%s] iRODS_handle->zone = [%s]\n", iRODS_handle->hostname, iRODS_handle->port, myRodsEnv.rodsUserName, myRodsEnv.rodsZone, iRODS_handle->user, iRODS_handle->zone);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: calling _rcConnect(%s,%i,%s,%s, %s, %s)\n", iRODS_handle->hostname, iRODS_handle->port, myRodsEnv.rodsUserName, myRodsEnv.rodsZone, iRODS_handle->user, iRODS_handle->zone);
            iRODS_handle->conn = _rcConnect(iRODS_handle->hostname, iRODS_handle->port, myRodsEnv.rodsUserName, myRodsEnv.rodsZone, iRODS_handle->user, iRODS_handle->zone, &errMsg, 0, 0);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: _rcConnect returned %i\n", 0);
        } else {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: calling rcConnect(%s,%i,%s,%s)\n", iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone);
            iRODS_handle->conn = rcConnect(iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone, 0, &errMsg);
        }
        if (iRODS_handle->conn == nullptr) {
            char *err_str = globus_common_create_string("rcConnect failed:: %s Host: '%s', Port: '%i', UserName '%s', Zone '%s'\n",
                    errMsg.msg, iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone);
            result = GlobusGFSErrorGeneric(err_str);
            goto connect_error;
        }

        status = clientLogin(iRODS_handle->conn, nullptr, NULL);
        if (status != 0) {
            result = globus_l_gfs_iRODS_make_error("\'clientLogin\' failed.", status);
            goto error;
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: connected.\n");

        homeDirPattern = getenv(HOMEDIR_PATTERN);
        if (homeDirPattern == nullptr) { homeDirPattern = const_cast<char*>(DEFAULT_HOMEDIR_PATTERN); }
        finished_info.info.session.home_dir = globus_common_create_string(homeDirPattern, iRODS_handle->zone, iRODS_handle->user);
        free(user_name);

        globus_gridftp_server_set_checksum_support(op, "MD5:1;SHA256:2;SHA512:3;SHA1:4;ADLER32:10;");

        globus_gridftp_server_operation_finished(op, GLOBUS_SUCCESS, &finished_info);
        globus_free(finished_info.info.session.home_dir);
        return;
    }

    result = globus_l_gfs_iRODS_make_error("\'getRodsEnv\' failed.", status);
connect_error:
error:
    globus_gridftp_server_operation_finished(
        op, result, &finished_info);
}

/*************************************************************************
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 *  The dsi should clean up all memory they associated wit the session
 *  here.
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_destroy(
    void *                              user_arg)
{
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: %s called\n", __FUNCTION__);
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;

    if (user_arg != nullptr) {

        iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
        globus_mutex_destroy(&iRODS_handle->mutex);
        globus_fifo_destroy(&iRODS_handle->rh_q);
        iRODS_disconnect(iRODS_handle->conn);

        globus_free(iRODS_handle);
    };
}

/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    int                                 status;
    int                                 i;
    globus_gfs_stat_t *                 stat_array;
    globus_gfs_stat_t                   stat_buf;
    int                                 stat_count = 1;
    int                                 res = -1;
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    char *                              handle_server;
    char *                              URL;
    globus_result_t                     result;

    GlobusGFSName(globus_l_gfs_iRODS_stat);

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    /* first test for obvious directories */
    iRODS_l_reduce_path(stat_info->pathname);

    handle_server = getenv(PID_HANDLE_SERVER);
    if (handle_server != nullptr)
    {
        if (iRODS_handle->original_stat_path && iRODS_handle->resolved_stat_path)
        {
            // Replace original_stat_path with resolved_stat_path
            stat_info->pathname = str_replace(stat_info->pathname, iRODS_handle->original_stat_path, iRODS_handle->resolved_stat_path);
        }
        else if (iRODS_handle->original_stat_path == nullptr && iRODS_handle->resolved_stat_path == NULL)
        {
            // First stat: get only PID <prefix>/<suffix> from pathname.
            // During uploading, the object name appears after the path
            char* initPID = strdup(stat_info->pathname);
            int i, count;
            globus_bool_t isPID = GLOBUS_FALSE;
            for (i=0, count=0; initPID[i]; i++)
            {
                count += (initPID[i] == '/');
                if (count == 2)
                {
                    isPID = GLOBUS_TRUE;
                }
                if (count == 3)
                {
                    break;
                }
            }
            if (isPID == GLOBUS_TRUE)
            {

                char PID[i + 1];
                strncpy(PID, initPID, i);
                PID[i] = '\0';

                iRODS_handle->original_stat_path = strdup(PID);
                //iRODS_handle->resolved_stat_path = strdup(stat_info->pathname);

                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: if '%s' is a PID the Handle Server '%s' will resolve it!!\n", PID, handle_server);

                // Let's try to resolve the PID
                res = manage_pid(handle_server, PID, &URL);
                if (res == 0)
                {
                    // PID resolved
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: the Handle Server returned the URL: %s\n", URL);
                    // Remove iRODS host from URL
                    char *s = strstr(URL, iRODS_handle->hostname);
                    if(s != nullptr)
                    {
                        char *c = strstr(s, "/");
                        // Remove last "/" from returned URL
                        if (c && c[(strlen(c) - 1)] == '/')
                        {
                            c[strlen(c) - 1] = 0;
                        }
                        iRODS_handle->resolved_stat_path = strdup(c);
                        // replace the stat_info->pathname so that the stat and the folder transfer is done on the returned iRODS URL
                        stat_info->pathname = str_replace(stat_info->pathname, PID, iRODS_handle->resolved_stat_path);
                    }
                    else
                    {
                        // Manage scenario with a returned URL pointing to a different iRODS host (report an error)
                        char *err_str = globus_common_create_string("iRODS DSI: the Handle Server '%s' returnd the URL '%s' which is not managed by this GridFTP server which is connected through the iRODS DSI to: %s\n", handle_server, URL, iRODS_handle->hostname);
                        result = GlobusGFSErrorGeneric(err_str);
                        goto error;
                    }
                }
                else if (res == 1)
                {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: unable to resolve the PID with the Handle Server\n");
                }
                else
                {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: unable to resolve the PID. The Handle Server returned the response code: %i\n", res);
                }
            }
            else
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: this is not a valid PID: %s\n", stat_info->pathname);
            }
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: stat_info->pathname=%s\n", stat_info->pathname);
        if (iRODS_handle->resolved_stat_path)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: iRODS_handle->resolved_stat_path=%s\n", iRODS_handle->resolved_stat_path);
        }
    }

    status = iRODS_l_stat1(iRODS_handle->conn, &stat_buf, stat_info->pathname);
    if (status == -808000 || status == -310000)
    {
        result = globus_l_gfs_iRODS_make_error("No such file or directory.", status); //UberFTP NEEDS "No such file or directory" in error message
        goto error;
    }
    else if(status < 0)
    {
        result = globus_l_gfs_iRODS_make_error("iRODS_l_stat1 failed.", status);
        goto error;
    }
    /* iRODSFileStat */
    if(!S_ISDIR(stat_buf.mode) || stat_info->file_only)
    {
        stat_array = (globus_gfs_stat_t *) globus_calloc(
             1, sizeof(globus_gfs_stat_t));
         memcpy(stat_array, &stat_buf, sizeof(globus_gfs_stat_t));
    }
    else
    {
        int rc;
        free(stat_buf.name);

        // jjames - iRODS_l_stat_dir sends partial listings via globus_gridftp_server_finished_stat_partial,
        // any left over the rest will be handled below as normal
        rc = iRODS_l_stat_dir(op, iRODS_handle->conn, &stat_array, &stat_count, stat_info->pathname, iRODS_handle->user);
        if(rc != 0)
        {
            result = globus_l_gfs_iRODS_make_error("iRODS_l_stat_dir failed.", rc);
            goto error;
        }

    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: calling globus_gridftp_server_finished_stat\n");
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    /* gota free the names */
    for(i = 0; i < stat_count; i++)
    {
        globus_free(stat_array[i].name);
    }
    globus_free(stat_array);
    return;

error:
    globus_gridftp_server_finished_stat(op, result, nullptr, 0);
}

extern "C"
globus_result_t globus_l_gfs_iRODS_realpath(
        const char *                        in_path,
        char **                             out_realpath,
        void *                              user_arg) {

    GlobusGFSName(globus_l_gfs_iRODS_realpath);

    globus_l_gfs_iRODS_handle_t *       iRODS_handle;

    int                                 res = -1;
    char *                              handle_server;
    char *                              URL;
    globus_result_t                     result = 0;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    if(iRODS_handle == nullptr)
    {
        /* dont want to allow clear text so error out here */
        return GlobusGFSErrorGeneric("iRODS DSI must be a default backend module. It cannot be an eret alone");
    }

    *out_realpath = strdup(in_path);
    if(*out_realpath == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS DSI: strdup failed");
    }

    handle_server = getenv(PID_HANDLE_SERVER);
    if (result == 0 && handle_server != nullptr)
    {
        // single file transfer (stat has not been called); I need to try to resolve the PID
        char* initPID = strdup(*out_realpath);
        int i, count;
        for (i=0, count=0; initPID[i]; i++)
        {
            count += (initPID[i] == '/');
            if (count == 3)
            {
                break;
            }
        }
        char PID[i + 1];
        strncpy(PID, initPID, i);
        PID[i] = '\0';

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: (%s) if '%s' is a PID the Handle Server '%s' will resolve it!\n", __FUNCTION__, PID, handle_server);

        // Let's try to resolve the PID
        res = manage_pid(handle_server, PID, &URL);
        if (res == 0)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: (%s) the Handle Server returned the URL: %s\n", __FUNCTION__, URL);
            // Remove iRODS host from URL
            char *s = strstr(URL, iRODS_handle->hostname);
            if (s != nullptr)
            {
                char *c = strstr(s, "/");
                // set the resolved URL has collection to be trasnferred
                //collection = strdup(c);

               *out_realpath = str_replace(*out_realpath, PID, c);
            }
            else
            {
                // Manage scenario with a returned URL pointing to a different iRODS host (report an error)
                char *err_str = globus_common_create_string("iRODS DSI: (%s) the Handle Server '%s' returnd the URL '%s' which is not managed by this GridFTP server which is connected through the iRODS DSI to: %s\n", __FUNCTION__, handle_server, URL, iRODS_handle->hostname);
                result = GlobusGFSErrorGeneric(err_str);
            }
        }
        else if (res == 1)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: (%s) unable to resolve the PID with the Handle Server\n", __FUNCTION__);
        }
        else
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: (%s) unable to resolve the PID. The Handle Server returned the response code: %i\n", __FUNCTION__, res);
        }
    }

    if (result == 0) {
        iRODS_l_reduce_path(*out_realpath);
    } else {
        free(*out_realpath);
        *out_realpath = nullptr;
    }

    return result;
}

void *send_cksum_updates(void *args)
{
    time_t last_update_time = time(0);
    time_t now = time(0);

    cksum_thread_args_t *cksum_args = (cksum_thread_args_t*)args;

    // get update interval from server, locking for "op" although not necessary right now

    while (true) {

        pthread_mutex_lock(cksum_args->mutex);

        bool break_out = *cksum_args->done_flag;

        // send op
        if (!break_out && now - last_update_time > *cksum_args->update_interval) {

            // send update with globus_gridftp_server_intermediate_command
            char size_t_str[32];
            snprintf(size_t_str, 32, "%zu", *cksum_args->bytes_processed);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: calling globus_gridftp_server_intermediate_command with %s\n", size_t_str);
            globus_gridftp_server_intermediate_command(*cksum_args->op, GLOBUS_SUCCESS, size_t_str);
            last_update_time = time(0);
        }

        pthread_mutex_unlock(cksum_args->mutex);

        if (break_out) {
            break;
        }

        sleep(1);
        now = time(0);
    }

    return nullptr;

}

/*************************************************************************
 *  command
 *  -------
 *  This interface function is called when the client sends a 'command'.
 *  commands are such things as mkdir, remdir, delete.  The complete
 *  enumeration is below.
 *
 *  To determine which command is being requested look at:
 *      cmd_info->command
 *
 *      GLOBUS_GFS_CMD_MKD = 1,
 *      GLOBUS_GFS_CMD_RMD,
 *      GLOBUS_GFS_CMD_DELE,
 *      GLOBUS_GFS_CMD_RNTO,
 *      GLOBUS_GFS_CMD_RNFR,
 *      GLOBUS_GFS_CMD_CKSM,
 *      GLOBUS_GFS_CMD_SITE_CHMOD,
 *      GLOBUS_GFS_CMD_SITE_DSI
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: %s called\n", __FUNCTION__);
    int                                 status = 0;
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    char *                              collection;
    globus_result_t                     result = 0;
    char *                              handle_server;
    char *                              error_str;
    char *                              outChksum = GLOBUS_NULL;
    GlobusGFSName(globus_l_gfs_iRODS_command);

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;

    handle_server = getenv(PID_HANDLE_SERVER);
    if (handle_server != nullptr)
    {
        if (iRODS_handle->original_stat_path && iRODS_handle->resolved_stat_path)
        {
            // Replace original_stat_path with resolved_stat_path
            cmd_info->pathname = str_replace(cmd_info->pathname, iRODS_handle->original_stat_path, iRODS_handle->resolved_stat_path);
        }
    }

    collection = strdup(cmd_info->pathname);
    iRODS_l_reduce_path(collection);
    if(collection == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS DSI: strdup failed");
        globus_gridftp_server_finished_command(op, result, GLOBUS_NULL);
        return;
    }

    // variables used for checksum update thread
    bool checksum_update_thread_started = false;
    pthread_t update_thread;
    bool checksum_done_flag = false;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    size_t checksum_bytes_processed = 0;

    switch(cmd_info->command)
    {
        case GLOBUS_GFS_CMD_MKD:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: GLOBUS_GFS_CMD_MKD\n");
                collInp_t collCreateInp;
                bzero (&collCreateInp, sizeof (collCreateInp));
                rstrcpy (collCreateInp.collName, collection, MAX_NAME_LEN);
                addKeyVal (&collCreateInp.condInput, RECURSIVE_OPR__KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: rcCollCreate collection=%s\n", collection);
                status = rcCollCreate (iRODS_handle->conn, &collCreateInp);
            }
            break;

        case GLOBUS_GFS_CMD_RMD:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: GLOBUS_GFS_CMD_RMD\n");
                collInp_t rmCollInp;
                bzero (&rmCollInp, sizeof (rmCollInp));
                rstrcpy (rmCollInp.collName, collection, MAX_NAME_LEN);
                addKeyVal (&rmCollInp.condInput, FORCE_FLAG_KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: rcRmColl: collection=%s\n", collection);
                status = rcRmColl (iRODS_handle->conn, &rmCollInp,0);
            }
            break;

        case GLOBUS_GFS_CMD_DELE:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: GLOBUS_GFS_CMD_DELE\n");
                dataObjInp_t dataObjInp;
                bzero (&dataObjInp, sizeof (dataObjInp));
                rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
                addKeyVal (&dataObjInp.condInput, FORCE_FLAG_KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: rcDataObjUnlink: collection=%s\n", collection);
                status = rcDataObjUnlink(iRODS_handle->conn, &dataObjInp);
            }
            break;

        case GLOBUS_GFS_CMD_CKSM:
           {
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: GLOBUS_GFS_CMD_CKSUM\n");
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: algorithm=%s\n", cmd_info->cksm_alg);
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: collection=%s\n", collection);

               // look up checksum in metadata
               std::string checksum_algorithm_upper(cmd_info->cksm_alg);
               boost::to_upper(checksum_algorithm_upper);
               std::string checksum_avu_name = CHECKSUM_AVU_NAMESPACE + "::" + checksum_algorithm_upper;

               std::string logical_path{collection};

               const auto& vps = irods::get_virtual_path_separator();
               std::string::size_type pos = logical_path.find_last_of(vps);
               std::string data_name{logical_path.substr(pos+1, std::string::npos)};
               std::string coll_name{logical_path.substr(0, pos)};

               // get client requested update interval, if it is zero then client
               // has not requested updates
               int update_interval;
               globus_gridftp_server_get_update_interval(op, &update_interval);
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: client set update_interval to %d\n", update_interval);

               if (update_interval > 0) {

                   // client requested periodic updates
                   cksum_thread_args_t cksum_args = {&checksum_done_flag, &op, &mutex, &update_interval, &checksum_bytes_processed};

                   int result;
                   if ((result = pthread_create(&update_thread, nullptr, send_cksum_updates, &cksum_args)) != 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: could not create cksum update thread so no intermediate updates will occur [result=%d]\n", result);
                   } else {
                       checksum_update_thread_started = true;
                   }
               }

               //SELECT META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS, MIN(DATA_MODIFY_TIME) where COLL_NAME = '/tempZone/home/rods' and DATA_NAME = 'medium_file' and DATA_REPL_STATUS = '1'
               std::string metadata_query_str =
                    boost::str(boost::format(
                    "SELECT META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS, MIN(DATA_MODIFY_TIME) "
                    "WHERE META_DATA_ATTR_NAME = '%s' AND DATA_NAME = '%s' AND COLL_NAME = '%s' AND DATA_REPL_STATUS = '1'") %
                    checksum_avu_name %
                    data_name %
                    coll_name);

                std::string checksum_value;
                std::string timestamp;
                std::string modify_time;
                bool found_checksum = false;
                for(const auto& row : irods::query<rcComm_t>{iRODS_handle->conn, metadata_query_str}) {
                    checksum_value = row[0];
                    timestamp   = row[1];
                    modify_time = row[2];
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: Searching for %s, value=%s, timestamp=%s, data_modify_time=%s\n",
                            checksum_avu_name.c_str(), checksum_value.c_str(), timestamp.c_str(), modify_time.c_str());

                    // found a checksum for this protocol check the timestamp and
                    // compare it to the modify time
                    int timestamp_int;
                    int modify_time_int;
                    try {
                          timestamp_int = boost::lexical_cast<int>(timestamp);
                          modify_time_int = boost::lexical_cast<int>(modify_time);

                          if (timestamp_int > modify_time_int) {

                              outChksum = strdup(checksum_value.c_str());
                              found_checksum = true;
                              break;
                          }
                    } catch ( const boost::bad_lexical_cast& ) {}

                    // if we reach here, we found metadata but it
                    // is not valid or too old, delete the metadata
                    modAVUMetadataInp_t modAVUMetadataInp{};
                    char arg0[MAX_NAME_LEN];
                    char arg1[MAX_NAME_LEN];
                    char arg3[MAX_NAME_LEN];
                    char arg4[MAX_NAME_LEN];
                    char arg5[MAX_NAME_LEN];
                    snprintf( arg0, sizeof( arg0 ), "%s", "rm");
                    snprintf( arg1, sizeof( arg1 ), "%s", "-d");
                    snprintf( arg3, sizeof( arg3 ), "%s", checksum_avu_name.c_str());
                    snprintf( arg4, sizeof( arg4 ), "%s", checksum_value.c_str());
                    snprintf( arg5, sizeof( arg5 ), "%s", timestamp.c_str());
                    modAVUMetadataInp.arg0 = arg0;
                    modAVUMetadataInp.arg1 = arg1;
                    modAVUMetadataInp.arg2 = collection;
                    modAVUMetadataInp.arg3 = arg3;
                    modAVUMetadataInp.arg4 = arg4;
                    modAVUMetadataInp.arg5 = arg5;
                    rcModAVUMetadata(iRODS_handle->conn, &modAVUMetadataInp);
               }

               if (found_checksum) {
                   break;
               }

               // get the hasher
               irods::globus::Hasher hasher;
               std::string checksum_algorithm_lower(cmd_info->cksm_alg);
               boost::to_lower(checksum_algorithm_lower);
               irods::error ret = irods::globus::getHasher(
                                      checksum_algorithm_lower.c_str(),
                                      hasher );
               if ( !ret.ok() ) {
                   globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: Could not get hasher for %s\n", checksum_algorithm_lower.c_str());
                   status = ret.code();
                   break;
               }

               // read file and calculate hash
               constexpr unsigned int HASH_BUF_SZ = 1024*1024;

               dataObjInp_t inp_obj{};
               inp_obj.createMode = 0600;
               inp_obj.openFlags = O_RDONLY;
               rstrcpy(inp_obj.objPath, collection, MAX_NAME_LEN);
               int fd = rcDataObjOpen(iRODS_handle->conn, &inp_obj);
               if (fd < 3) {
                   status = -1;
                   globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: rcDataObjOpen returned invalid file descriptor = %d\n", fd);
                   break;
               }

               char buffer_read[HASH_BUF_SZ];

               openedDataObjInp_t input{};
               input.l1descInx = fd;
               input.len = HASH_BUF_SZ;

               bytesBuf_t output{};
               output.len = input.len;
               output.buf = buffer_read;

               int length_read = 0;
               while ((length_read = rcDataObjRead(iRODS_handle->conn, &input, &output)) > 0) {

                   pthread_mutex_lock(&mutex);
                   checksum_bytes_processed += length_read;
                   pthread_mutex_unlock(&mutex);

                   std::string s(static_cast<char*>(output.buf), length_read);
                   hasher.update(s);
               }

               rcDataObjClose(iRODS_handle->conn, &input);

               std::string digest;
               hasher.digest( digest );
               std::string hex_output;

               // remove prefixes that iRODS puts on checksums
               size_t offset = digest.find(':');
               if (offset != std::string::npos) {
                   digest = digest.substr(offset + 1);
               }

               // in cases where base64 is used, convert to hex
               if (checksum_algorithm_upper == "SHA256") {
                   status = convert_base64_to_hex_string(digest, 256, hex_output);
                   if (status < 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: could not convert base64 to hex\n");
                       break;
                   }
                   outChksum = strdup(hex_output.c_str());
               } else if (checksum_algorithm_upper == "SHA512") {
                   status = convert_base64_to_hex_string(digest, 512, hex_output);
                   if (status < 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: could not convert base64 to hex\n");
                       break;
                   }
                   outChksum = strdup(hex_output.c_str());
               } else if (checksum_algorithm_upper == "SHA1") {
                   status = convert_base64_to_hex_string(digest, 160, hex_output);
                   if (status < 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: could not convert base64 to hex\n");
                       break;
                   }
                   outChksum = strdup(hex_output.c_str());
               } else {
                   outChksum = strdup(digest.c_str());
               }

               // get current time
               int current_epoch_time = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch()).count();

               // write metadata
               modAVUMetadataInp_t modAVUMetadataInp{};
               char arg0[MAX_NAME_LEN];
               char arg1[MAX_NAME_LEN];
               char arg3[MAX_NAME_LEN];
               char arg5[MAX_NAME_LEN];
               snprintf( arg0, sizeof( arg0 ), "%s", "add");
               snprintf( arg1, sizeof( arg1 ), "%s", "-d");
               snprintf( arg3, sizeof( arg3 ), "%s", checksum_avu_name.c_str());
               snprintf( arg5, sizeof( arg5 ), "%s", std::to_string(current_epoch_time).c_str());
               modAVUMetadataInp.arg0 = arg0;
               modAVUMetadataInp.arg1 = arg1;
               modAVUMetadataInp.arg2 = collection;
               modAVUMetadataInp.arg3 = arg3;
               modAVUMetadataInp.arg4 = outChksum;
               modAVUMetadataInp.arg5 = arg5;
               rcModAVUMetadata(iRODS_handle->conn, &modAVUMetadataInp);

           }

           break;

        default:
            break;
    }

    free(collection);

    if(status < 0)
    {
        error_str = globus_common_create_string("iRODS DSI error: status = %d", status);
        result = GlobusGFSErrorGeneric(error_str);
    }

    if (checksum_update_thread_started) {

        pthread_mutex_lock(&mutex);
        checksum_done_flag = true;
        pthread_mutex_unlock(&mutex);

        if (pthread_join(update_thread, nullptr) != 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: could not join with cksum update thread.  continuing...\n");
        }
    }

    globus_gridftp_server_finished_command(op, result, outChksum);

}

/*************************************************************************
 *  recv
 *  ----
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 *  To receive a file the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_read();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    int                                 flags = O_WRONLY;
    globus_bool_t                       finish = GLOBUS_FALSE;
    char *                              collection = nullptr;
    //char *                              handle_server;
    dataObjInp_t                        dataObjInp;
    openedDataObjInp_t                  dataObjWriteInp;
    int result;

    GlobusGFSName(globus_l_gfs_iRODS_recv);
    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;

    if(transfer_info->pathname == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS DSI: transfer_info->pathname == nullptr");
        goto alloc_error;
    }

    collection = strdup(transfer_info->pathname);
    iRODS_l_reduce_path(collection);

    //Get iRODS resource from destination path
    if (getenv(IRODS_RESOURCE_MAP) !=nullptr)
    {
        if(iRODS_Resource_struct.resource != nullptr && iRODS_Resource_struct.path != NULL)
        {
            if(strncmp(iRODS_Resource_struct.path, transfer_info->pathname, strlen(iRODS_Resource_struct.path)) != 0 )
            {
                iRODS_getResource(transfer_info->pathname);
            }
        }
        else
        {
             iRODS_getResource(transfer_info->pathname);
        }
    }

    if(iRODS_handle == nullptr)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("iRODS DSI must be a default backend"
            " module.  It cannot be an eret alone");
        goto alloc_error;
    }

    if(transfer_info->truncate)
    {
        flags |= O_TRUNC;
    }

    bzero (&dataObjInp, sizeof (dataObjInp));
    rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
    dataObjInp.openFlags = flags;
    // give priority to explicit resource mapping, otherwise use default resource if set
    if (iRODS_Resource_struct.resource != nullptr)
    {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_Resource_struct.resource);
    } else if (iRODS_handle->defResource != nullptr ) {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_handle->defResource);
    };
    iRODS_handle->fd = rcDataObjOpen (iRODS_handle->conn, &dataObjInp);

    if (iRODS_handle->fd > 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: Open existing object: %s.\n", collection);
    }
    else
    {
        //create the obj
        bzero (&dataObjInp, sizeof (dataObjInp));
        bzero (&dataObjWriteInp, sizeof (dataObjWriteInp));
        rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
        dataObjInp.dataSize = 0;
        // set operation type to PUT, otherwise acPostProcForPut rules will not fire through GridFTP uploads.
        dataObjInp.oprType = PUT_OPR;
        addKeyVal (&dataObjInp.condInput, FORCE_FLAG_KW, "");
        // give priority to explicit resource mapping, otherwise use default resource if set
        if (iRODS_Resource_struct.resource != nullptr)
        {
            addKeyVal (&dataObjInp.condInput, DEST_RESC_NAME_KW, iRODS_Resource_struct.resource);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: Creating file with resource: %s\n", iRODS_Resource_struct.resource);
        } else if (iRODS_handle->defResource != nullptr ) {
            addKeyVal (&dataObjInp.condInput, DEST_RESC_NAME_KW, iRODS_handle->defResource);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: Creating file with default resource: %s\n", iRODS_handle->defResource);
        }
        iRODS_handle->fd = rcDataObjCreate (iRODS_handle->conn, &dataObjInp);
        if (iRODS_handle->fd < 0) {
            result = globus_l_gfs_iRODS_make_error("rcDataObjCreate failed", iRODS_handle->fd);
            goto error;
        }
        else
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: Creating file succeeded. File created: %s.\n", collection);
        }
    }

    free(collection);

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    /* reset all the needed variables in the handle */
    iRODS_handle->cached_res = GLOBUS_SUCCESS;
    iRODS_handle->outstanding = 0;
    iRODS_handle->done = GLOBUS_FALSE;
    iRODS_handle->blk_length = 0;
    iRODS_handle->blk_offset = 0;
    iRODS_handle->op = op;
    globus_gridftp_server_get_block_size(
        op, &iRODS_handle->block_size);

    globus_gridftp_server_begin_transfer(op, 0, iRODS_handle);

    globus_mutex_lock(&iRODS_handle->mutex);
    {
        finish = globus_l_gfs_iRODS_read_from_net(iRODS_handle);
    }
    globus_mutex_unlock(&iRODS_handle->mutex);

    if(finish)
    {
        globus_gridftp_server_finished_transfer(iRODS_handle->op, iRODS_handle->cached_res);
    }

    return;

error:
alloc_error:
    globus_gridftp_server_finished_transfer(op, result);

}

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_bool_t                       done = GLOBUS_FALSE;
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    globus_result_t                     result;
    char *                              collection;

    int                                 i = 0;
    int                                 res = -1;
    char *                              handle_server;
    char *                              URL;
    dataObjInp_t                        dataObjInp;

    GlobusGFSName(globus_l_gfs_iRODS_send);

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    if(iRODS_handle == nullptr)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("iRODS DSI must be a default backend module. It cannot be an eret alone");
        goto alloc_error;
    }

    collection = strdup(transfer_info->pathname);
    if(collection == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS DSI: strdup failed");
        goto alloc_error;
    }

    handle_server = getenv(PID_HANDLE_SERVER);
    if (handle_server != nullptr)
    {
       if (iRODS_handle->original_stat_path && iRODS_handle->resolved_stat_path)
        {
            // Replace original_stat_path with resolved_stat_path
            collection = str_replace(transfer_info->pathname, iRODS_handle->original_stat_path, iRODS_handle->resolved_stat_path);
            res = 0;
        }
        else if (iRODS_handle->original_stat_path == nullptr && iRODS_handle->resolved_stat_path == NULL)
        {
            // single file transfer (stat has not been called); I need to try to resolve the PID
            char* initPID = strdup(transfer_info->pathname);
            int i, count;
            for (i=0, count=0; initPID[i]; i++)
            {
                count += (initPID[i] == '/');
                if (count == 3)
                {
                    break;
                }
            }
            char PID[i + 1];
            strncpy(PID, initPID, i);
            PID[i] = '\0';

            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: if '%s' is a PID the Handle Server '%s' will resolve it!\n", PID, handle_server);

            // Let's try to resolve the PID
            res = manage_pid(handle_server, PID, &URL);
            if (res == 0)
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: the Handle Server returned the URL: %s\n", URL);
                // Remove iRODS host from URL
                char *s = strstr(URL, iRODS_handle->hostname);
                if (s != nullptr)
                {
                    char *c = strstr(s, "/");
                    // set the resolved URL has collection to be trasnferred
                    //collection = strdup(c);

                   collection = str_replace(transfer_info->pathname, PID, c);
                }
                else
                {
                    // Manage scenario with a returned URL pointing to a different iRODS host (report an error)
                    char *err_str = globus_common_create_string("iRODS DSI: the Handle Server '%s' returnd the URL '%s' which is not managed by this GridFTP server which is connected through the iRODS DSI to: %s\n", handle_server, URL, iRODS_handle->hostname);
                    result = GlobusGFSErrorGeneric(err_str);
                    goto error;
                }
            }
            else if (res == 1)
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: unable to resolve the PID with the Handle Server\n");
            }
            else
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: unable to resolve the PID. The Handle Server returned the response code: %i\n", res);
            }
        }
    }

    iRODS_l_reduce_path(collection);

    //Get iRODS resource from destination path
    if (getenv(IRODS_RESOURCE_MAP) !=nullptr)
    {
        if(iRODS_Resource_struct.resource != nullptr && iRODS_Resource_struct.path != NULL)
        {
            if(strncmp(iRODS_Resource_struct.path, transfer_info->pathname, strlen(iRODS_Resource_struct.path)) != 0 )
            {
                iRODS_getResource(collection);
            }
        }
        else
        {
            iRODS_getResource(collection);
        }
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: retreiving '%s'\n", collection);
    bzero (&dataObjInp, sizeof (dataObjInp));
    rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
    // give priority to explicit resource mapping, otherwise use default resource if set
    if (iRODS_Resource_struct.resource != nullptr)
    {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_Resource_struct.resource);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: retriving object with resource: %s\n", iRODS_Resource_struct.resource);
    }
    else if (iRODS_handle->defResource != nullptr ) {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_handle->defResource);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS DSI: retrieving object from default resource: %s\n", iRODS_handle->defResource);
    };

    iRODS_handle->fd = rcDataObjOpen (iRODS_handle->conn, &dataObjInp);

    if (iRODS_handle->fd < 0) {
        char *error_str;
        if (handle_server != nullptr)
            if (res == 0) {
                error_str = globus_common_create_string("rcDataObjOpen failed opening '%s' (the DSI has succesfully resolved the PID through the Handle Server '%s.)", collection, handle_server);
            }
            else
            {
                error_str = globus_common_create_string("rcDataObjOpen failed opening '%s' (the DSI has also tryed to manage the path as a PID but the resolution through the Handle Server '%s' failed)", collection, handle_server);
            }
        else
        {
            error_str = globus_common_create_string("rcDataObjOpen failed opening '%s'\n", collection);
        }
        result = globus_l_gfs_iRODS_make_error(error_str, iRODS_handle->fd);
        free(error_str);
        goto error;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS DSI: rcDataObjOpen: %s\n", collection);

    /* reset all the needed variables in the handle */
    iRODS_handle->read_eof = GLOBUS_FALSE;
    iRODS_handle->cached_res = GLOBUS_SUCCESS;
    iRODS_handle->outstanding = 0;
    iRODS_handle->done = GLOBUS_FALSE;
    iRODS_handle->blk_length = 0;
    iRODS_handle->blk_offset = 0;
    iRODS_handle->op = op;
    globus_gridftp_server_get_optimal_concurrency(
        op, &iRODS_handle->optimal_count);
    globus_gridftp_server_get_block_size(
        op, &iRODS_handle->block_size);

    globus_gridftp_server_begin_transfer(op, 0, iRODS_handle);

    globus_mutex_lock(&iRODS_handle->mutex);
    {

        for(i = 0; i < iRODS_handle->optimal_count && !done; i++)
        {
            globus_l_gfs_iRODS_read_ahead_next(iRODS_handle);
            done = globus_l_gfs_iRODS_send_next_to_client(iRODS_handle);
        }
        for(i = 0; i < iRODS_handle->optimal_count && !done; i++)
        {
            globus_l_gfs_iRODS_read_ahead_next(iRODS_handle);
        }
        if(done && iRODS_handle->outstanding == 0 &&
            globus_fifo_empty(&iRODS_handle->rh_q))
        {
            finish = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&iRODS_handle->mutex);
    if(finish)
    {
        globus_gridftp_server_finished_transfer(op, iRODS_handle->cached_res);
    }

    globus_free(collection);
    return;

error:
    globus_free(collection);
alloc_error:
    globus_gridftp_server_finished_transfer(op, result);
}

/*************************************************************************
 *         logic to receive from client
 *         ----------------------------
 ************************************************************************/

static
void
globus_l_gfs_iRODS_net_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg)
{
    globus_bool_t                       finished = GLOBUS_FALSE;
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    int                                 bytes_written;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;

    globus_mutex_lock(&iRODS_handle->mutex);
    {
        if(eof)
        {
            iRODS_handle->done = GLOBUS_TRUE;
        }
        iRODS_handle->outstanding--;
        if(result != GLOBUS_SUCCESS)
        {
            iRODS_handle->cached_res = result;
            iRODS_handle->done = GLOBUS_TRUE;
        }
        /* if the read was successful write to disk */
        else if(nbytes > 0)
        {
            openedDataObjInp_t dataObjLseekInp;
            bzero (&dataObjLseekInp, sizeof (dataObjLseekInp));
            dataObjLseekInp.l1descInx = iRODS_handle->fd;
            fileLseekOut_t *dataObjLseekOut = nullptr;
            dataObjLseekInp.offset = offset;
            dataObjLseekInp.whence = SEEK_SET;

            int status = rcDataObjLseek(iRODS_handle->conn, &dataObjLseekInp, &dataObjLseekOut);
            // verify that it worked
            if(status < 0)
            {
                iRODS_handle->cached_res = globus_l_gfs_iRODS_make_error("rcDataObjLseek failed", status);
                iRODS_handle->done = GLOBUS_TRUE;
            }
            else
            {
               openedDataObjInp_t dataObjWriteInp;
               bzero (&dataObjWriteInp, sizeof (dataObjWriteInp));
               dataObjWriteInp.l1descInx = iRODS_handle->fd;
               dataObjWriteInp.len = nbytes;

               bytesBuf_t dataObjWriteInpBBuf;
               dataObjWriteInpBBuf.buf = buffer;
               dataObjWriteInpBBuf.len = nbytes;

               bytes_written  = rcDataObjWrite(iRODS_handle->conn, &dataObjWriteInp, &dataObjWriteInpBBuf); //buffer need to be casted??
               if (bytes_written < dataObjWriteInp.len) {
                   // erroring on any short write instead of only bytes_written < 0
                   iRODS_handle->cached_res = globus_l_gfs_iRODS_make_error("rcDataObjWrite failed", bytes_written);
                   iRODS_handle->done = GLOBUS_TRUE;
               }
               else
               {
                   globus_gridftp_server_update_bytes_written(op, offset, bytes_written);
               }
            }
        }

        globus_free(buffer);
        /* if not done just register the next one */
        if(!iRODS_handle->done)
        {
            finished = globus_l_gfs_iRODS_read_from_net(iRODS_handle);
        }
        /* if done and there are no outstanding callbacks finish */
        else if(iRODS_handle->outstanding == 0)
        {
            openedDataObjInp_t dataObjCloseInp;
            bzero (&dataObjCloseInp, sizeof (dataObjCloseInp));
            dataObjCloseInp.l1descInx = iRODS_handle->fd;
            rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
            finished = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&iRODS_handle->mutex);

    if(finished)
    {
        globus_gridftp_server_finished_transfer(op, iRODS_handle->cached_res);
    }
}

static
globus_bool_t
globus_l_gfs_iRODS_read_from_net(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     result;
    GlobusGFSName(globus_l_gfs_iRODS_read_from_net);

    /* in the read case tis number will vary */
    globus_gridftp_server_get_optimal_concurrency(
        iRODS_handle->op, &iRODS_handle->optimal_count);

    while(iRODS_handle->outstanding < iRODS_handle->optimal_count)
    {
        buffer = static_cast<unsigned char*>(globus_malloc(iRODS_handle->block_size));
        if(buffer == nullptr)
        {
            result = GlobusGFSErrorGeneric("malloc failed");
            goto error;
        }
        result = globus_gridftp_server_register_read(
            iRODS_handle->op,
            buffer,
            iRODS_handle->block_size,
            globus_l_gfs_iRODS_net_read_cb,
            iRODS_handle);
        if(result != GLOBUS_SUCCESS)
        {
            goto alloc_error;
        }
        iRODS_handle->outstanding++;
    }

    return GLOBUS_FALSE;

alloc_error:
    globus_free(buffer);
error:
    iRODS_handle->cached_res = result;
    iRODS_handle->done = GLOBUS_TRUE;
    if(iRODS_handle->outstanding == 0)
    {
        openedDataObjInp_t dataObjCloseInp;
        bzero (&dataObjCloseInp, sizeof (dataObjCloseInp));
        dataObjCloseInp.l1descInx = iRODS_handle->fd;
        rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
        return GLOBUS_TRUE;
    }
    return GLOBUS_FALSE;
}

/*************************************************************************
 *         logic for sending to the client
 *         ----------------------------
 ************************************************************************/
static
void
globus_l_gfs_net_write_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_bool_t                       finish = GLOBUS_FALSE;
    globus_l_gfs_iRODS_handle_t *         iRODS_handle;
    globus_l_iRODS_read_ahead_t *         rh;
    globus_l_iRODS_read_ahead_t *         tmp_rh;

    rh = (globus_l_iRODS_read_ahead_t *) user_arg;
    iRODS_handle = rh->iRODS_handle;
    free(rh->buffer);
    globus_free(rh);

    globus_mutex_lock(&iRODS_handle->mutex);
    {
        iRODS_handle->outstanding--;
        if(result != GLOBUS_SUCCESS)
        {
            iRODS_handle->cached_res = result;
            iRODS_handle->read_eof = GLOBUS_TRUE;
            openedDataObjInp_t dataObjCloseInp;
            bzero (&dataObjCloseInp, sizeof (dataObjCloseInp));
            dataObjCloseInp.l1descInx = iRODS_handle->fd;
            rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
            while(!globus_fifo_empty(&iRODS_handle->rh_q))
            {
                tmp_rh = (globus_l_iRODS_read_ahead_t *)
                    globus_fifo_dequeue(&iRODS_handle->rh_q);
                free(rh->buffer);
                globus_free(tmp_rh);
            }
        }
        else
        {
            globus_l_gfs_iRODS_send_next_to_client(iRODS_handle);
            globus_l_gfs_iRODS_read_ahead_next(iRODS_handle);
        }
        /* if done and there are no outstanding callbacks finish */
        if(iRODS_handle->outstanding == 0 &&
            globus_fifo_empty(&iRODS_handle->rh_q))
        {
            finish = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&iRODS_handle->mutex);

    if(finish)
    {
        globus_gridftp_server_finished_transfer(op, iRODS_handle->cached_res);
    }
}

static
globus_bool_t
globus_l_gfs_iRODS_send_next_to_client(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle)
{
    globus_l_iRODS_read_ahead_t *         rh;
    globus_result_t                     res;
    GlobusGFSName(globus_l_gfs_iRODS_send_next_to_client);

    rh = (globus_l_iRODS_read_ahead_t *) globus_fifo_dequeue(&iRODS_handle->rh_q);
    if(rh == nullptr)
    {
        goto error;
    }

    res = globus_gridftp_server_register_write(
        iRODS_handle->op, rh->buffer, rh->length, rh->offset, -1,
        globus_l_gfs_net_write_cb, rh);
    if(res != GLOBUS_SUCCESS)
    {
        goto alloc_error;
    }
    iRODS_handle->outstanding++;
    return GLOBUS_FALSE;

alloc_error:
    globus_free(rh);

    iRODS_handle->cached_res = res;
    if(!iRODS_handle->read_eof)
    {
        openedDataObjInp_t dataObjCloseInp;
        bzero (&dataObjCloseInp, sizeof (dataObjCloseInp));
        dataObjCloseInp.l1descInx = iRODS_handle->fd;
        rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
        iRODS_handle->read_eof = GLOBUS_TRUE;
    }
    /* if we get an error here we need to flush the q */
    while(!globus_fifo_empty(&iRODS_handle->rh_q))
    {
        rh = (globus_l_iRODS_read_ahead_t *)
            globus_fifo_dequeue(&iRODS_handle->rh_q);
        globus_free(rh);
    }

error:
    return GLOBUS_TRUE;
}

static
void
globus_l_gfs_iRODS_read_ahead_next(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle)
{
    int                                 read_length;
    globus_result_t                     result;
    globus_l_iRODS_read_ahead_t *         rh;
    GlobusGFSName(globus_l_gfs_iRODS_read_ahead_next);

    bool error = false, attempt_error = false;

    if(iRODS_handle->read_eof)
    {
        error = true;
    }

    if (!error) {
        /* if we have done everything for this block, get the next block
           also this will happen the first time
           -1 length means until the end of the file  */

        if(iRODS_handle->blk_length == 0)
        {
            /* check the next range to read */
            globus_gridftp_server_get_read_range(
                iRODS_handle->op,
                &iRODS_handle->blk_offset,
                &iRODS_handle->blk_length);
            if(iRODS_handle->blk_length == 0)
            {
                result = GLOBUS_SUCCESS;
                error = true;
            }
        }

        if (!error) {
            /* get the current length to read */
            if(iRODS_handle->blk_length == -1 || iRODS_handle->blk_length > static_cast<globus_off_t>(iRODS_handle->block_size))
            {
                read_length = (int)iRODS_handle->block_size;
            }
            else
            {
                read_length = (int)iRODS_handle->blk_length;
            }
            rh = (globus_l_iRODS_read_ahead_t *) calloc(1,
                sizeof(globus_l_iRODS_read_ahead_t)+read_length);
            rh->offset = iRODS_handle->blk_offset;
            rh->iRODS_handle = iRODS_handle;

            openedDataObjInp_t dataObjLseekInp;
            bzero (&dataObjLseekInp, sizeof (dataObjLseekInp));
            dataObjLseekInp.l1descInx = iRODS_handle->fd;
            fileLseekOut_t *dataObjLseekOut = nullptr;
            dataObjLseekInp.offset = (long)iRODS_handle->blk_offset;
            dataObjLseekInp.whence = SEEK_SET;

            int status = rcDataObjLseek(iRODS_handle->conn, &dataObjLseekInp, &dataObjLseekOut);
            // verify that it worked
            if(status < 0)
            {
                result = globus_l_gfs_iRODS_make_error("rcDataObjLseek failed", status);
                attempt_error = true;
            }

            if (!attempt_error) {
                openedDataObjInp_t dataObjReadInp;
                bzero (&dataObjReadInp, sizeof (dataObjReadInp));
                dataObjReadInp.l1descInx = iRODS_handle->fd;
                dataObjReadInp.len = read_length;

                bytesBuf_t dataObjReadOutBBuf;
                bzero (&dataObjReadOutBBuf, sizeof (dataObjReadOutBBuf));

                rh->length = rcDataObjRead (iRODS_handle->conn, &dataObjReadInp, &dataObjReadOutBBuf);
                if(rh->length <= 0)
                {
                    result = GLOBUS_SUCCESS; /* this may just be eof */
                    attempt_error = true;
                }

                if (!attempt_error) {
                    rh->buffer =  (globus_byte_t *)dataObjReadOutBBuf.buf;
                    iRODS_handle->blk_offset += rh->length;
                    if(iRODS_handle->blk_length != -1)
                    {
                        iRODS_handle->blk_length -= rh->length;
                    }

                    globus_fifo_enqueue(&iRODS_handle->rh_q, rh);
                    return;
                }
            }
        }
    }

    if (attempt_error) {
        globus_free(rh);
        openedDataObjInp_t dataObjCloseInp;
        bzero (&dataObjCloseInp, sizeof (dataObjCloseInp));
        dataObjCloseInp.l1descInx = iRODS_handle->fd;
        rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
        iRODS_handle->cached_res = result;
    }

    iRODS_handle->read_eof = GLOBUS_TRUE;
}

extern "C"
int
globus_l_gfs_iRODS_activate(void);

extern "C"
int
globus_l_gfs_iRODS_deactivate(void);

/*
 *  no need to change this
 */
static globus_gfs_storage_iface_t       globus_l_gfs_iRODS_dsi_iface =
{
    GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER |
      GLOBUS_GFS_DSI_DESCRIPTOR_HAS_REALPATH,  // descriptor
    globus_l_gfs_iRODS_start,
    globus_l_gfs_iRODS_destroy,
    nullptr, /* list */
    globus_l_gfs_iRODS_send,
    globus_l_gfs_iRODS_recv,
    nullptr, /* trev */
    nullptr, /* active */
    nullptr, /* passive */
    nullptr, /* data destroy */
    globus_l_gfs_iRODS_command,
    globus_l_gfs_iRODS_stat,
    nullptr,
    nullptr,
    globus_l_gfs_iRODS_realpath
};

/*
 *  no need to change this
 */
GlobusExtensionDefineModule(globus_gridftp_server_iRODS) =
{
    const_cast<char*>("globus_gridftp_server_iRODS"),
    globus_l_gfs_iRODS_activate,
    globus_l_gfs_iRODS_deactivate,
    nullptr,
    nullptr,
    &local_version,
    nullptr
};

/*
 *  no need to change this
 */
int
globus_l_gfs_iRODS_activate(void)
{
    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        static_cast<void*>(const_cast<char*>("iRODS")),
        GlobusExtensionMyModule(globus_gridftp_server_iRODS),
        &globus_l_gfs_iRODS_dsi_iface);

    return 0;
}

/*
 *  no need to change this
 */
int
globus_l_gfs_iRODS_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY,
        static_cast<void*>(const_cast<char*>("iRODS")));

    return 0;
}
