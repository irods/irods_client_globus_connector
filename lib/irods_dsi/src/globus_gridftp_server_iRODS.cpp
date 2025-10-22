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
  #include "globus_range_list.h"
}
//#pragma GCC diagnostic pop

#ifdef IRODS_HEADER_HPP
  #include <irods/rodsClient.hpp>
#else
  #include <irods/rodsClient.h>
#endif

#include <irods/irods_query.hpp>
#include <irods/irods_string_tokenize.hpp>
#include <irods/irods_virtual_path.hpp>
#include <irods_hasher_factory.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/get_file_descriptor_info.h>
#include <irods/replica_close.h>
#include <irods/thread_pool.hpp>
#include <irods/filesystem.hpp>
#include <irods/base64.hpp>
#include <irods/touch.h>

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
#include <condition_variable>
#include <map>

// local includes
#include "circular_buffer.hpp"

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

/* if present, set the number or read/write threads for file transfers */
#define NUMBER_OF_IRODS_READ_WRITE_THREADS "numberOfIrodsReadWriteThreads"

/* if present, set the number or read/write threads for file transfers */
#define IRODS_PARALLEL_FILE_SIZE_THRESHOLD_BYTES "irodsParallelFileSizeThresholdBytes"

const static unsigned int DEFAULT_NUMBER_OF_IRODS_READ_WRITE_THREADS = 3;
const static unsigned int MAXIMUM_NUMBER_OF_IRODS_READ_WRITE_THREADS = 10;

const static std::string CHECKSUM_AVU_NAMESPACE{"GLOBUS"};

// map to translate globus_gfs_command_type_t values into strings for error messages
const static std::map<int, std::string> command_map = {
    { 1, "GLOBUS_GFS_CMD_MKD" },
    { 2, "GLOBUS_GFS_CMD_RMD" },
    { 3, "GLOBUS_GFS_CMD_DELE" },
    { 4, "GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT" },
    { 5, "GLOBUS_GFS_CMD_SITE_RDEL" },
    { 6, "GLOBUS_GFS_CMD_RNTO" },
    { 7, "GLOBUS_GFS_CMD_RNFR" },
    { 8, "GLOBUS_GFS_CMD_CKSM" },
    { 9, "GLOBUS_GFS_CMD_SITE_CHMOD" },
    { 10, "GLOBUS_GFS_CMD_SITE_DSI" },
    { 11, "GLOBUS_GFS_CMD_SITE_SETNETSTACK" },
    { 12, "GLOBUS_GFS_CMD_SITE_SETDISKSTACK" },
    { 13, "GLOBUS_GFS_CMD_SITE_CLIENTINFO" },
    { 14, "GLOBUS_GFS_CMD_DCSC" },
    { 15, "GLOBUS_GFS_CMD_SITE_CHGRP" },
    { 16, "GLOBUS_GFS_CMD_SITE_UTIME" },
    { 17, "GLOBUS_GFS_CMD_SITE_SYMLINKFROM" },
    { 18, "GLOBUS_GFS_CMD_SITE_SYMLINK" },
    { 19, "GLOBUS_GFS_CMD_HTTP_PUT" },
    { 21, "GLOBUS_GFS_CMD_HTTP_GET" },
    { 22, "GLOBUS_GFS_CMD_HTTP_CONFIG" },
    { 23, "GLOBUS_GFS_CMD_TRNC" },
    { 24, "GLOBUS_GFS_CMD_SITE_TASKID" },
    { 3072, "GLOBUS_GFS_CMD_SITE_RESTRICT" },
    { 3073, "GLOBUS_GFS_CMD_SITE_CHROOT" },
    { 3074, "GLOBUS_GFS_CMD_SITE_SHARING" },
    { 3075, "GLOBUS_GFS_CMD_UPAS" },
    { 3076, "GLOBUS_GFS_CMD_UPRT" },
    { 3077, "GLOBUS_GFS_CMD_STORATTR" },
    { 3078, "GLOBUS_GFS_CMD_WHOAMI" },
    { 4096, "GLOBUS_GFS_MIN_CUSTOM_CMD" }
};

const std::string get_command_string(const int i) {
    auto iter = command_map.find(i);
    if (iter != command_map.end()) {
        return iter->second;
    }
    return std::to_string(i);
}

// struct to save buffer to be written to iRODS
typedef struct read_write_buffer
{
    globus_byte_t *                     buffer;
    globus_size_t                       nbytes;
    globus_off_t                        offset;
} read_write_buffer_t;

// create reading and writing circular buffers (10 buffer entries and 30 second timeout)
irods::experimental::circular_buffer<read_write_buffer_t> irods_write_circular_buffer{10, 30};

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
    pthread_cond_t          *cond;
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

    int ret = irods::base64_decode(reinterpret_cast<const unsigned char*>(base64_str.c_str()), base64_str.size(), out, &out_len);

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

// removes all trailing slashes and replaces consecutive slashes with a single slash
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

/*
*  the data structure representing the FTP session
*/
struct globus_l_gfs_iRODS_handle_t
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

    // added for redesign (issue 33)
    char *                              adminUser;
    char *                              adminZone;
    char *                              replica_token;
    unsigned int                        number_of_irods_read_write_threads;
    uint64_t                            irods_parallel_file_size_threshold_bytes;

    bool                                first_write_done;

    // added to get file modification time from client
    time_t                              utime;
};

std::condition_variable             outstanding_cntr_cv;
std::mutex                          outstanding_cntr_mutex;

std::condition_variable             first_write_cv;
std::mutex                          first_write_mutex;

void print_irods_handle(globus_l_gfs_iRODS_handle_t& handle, char * file, int line)
{
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "%s:%d conn=%p \n", file, line, handle.conn);
}



typedef struct globus_l_iRODS_read_ahead_s
{
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
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
    rcComm_t *                           conn,
    const std::string&                   call_context_for_logging = "")

{
    if (conn) {
        rcDisconnect(conn);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s disconnected from iRODS.\n", call_context_for_logging.c_str());
    }
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
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: User found in irodsUserMap.conf: DN = %s, iRODS user = %s.\n",
                        DN, iRODS_user_name);
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
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: found iRODS resource  %s for destinationPath %s.\n",
                        iRODS_res, destinationPath);

                /* store the mapping in the global pointers in iRODS_Resource_struct - duplicating the string value.
                 * Free any previously stored (duplicated) string pointer first!
                 */
                if (iRODS_Resource_struct.resource != nullptr)
                {
                    free(iRODS_Resource_struct.resource);
                    iRODS_Resource_struct.resource = nullptr;
                };
                iRODS_Resource_struct.resource =  strdup(iRODS_res);
                if (iRODS_Resource_struct.path != nullptr)
                {
                    free(iRODS_Resource_struct.path);
                    iRODS_Resource_struct.path = nullptr;
                }
                iRODS_Resource_struct.path = strdup(path_Read);
                break;
            }
        }
        fclose ( file );
    }
    else
    {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: irodsResourceMap file not found: %s.\n", getenv(IRODS_RESOURCE_MAP));
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
    memset(&collHandle, 0, sizeof(collHandle));
    int queryFlags;
    queryFlags = DATA_QUERY_FIRST_FG | VERY_LONG_METADATA_FG | NO_TRIM_REPL_FG;
    status = rclOpenCollection (conn, start_dir, queryFlags,  &collHandle);
    if (status >= 0)
    {

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: found collection %s.\n", start_dir);
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
        memset (&dataObjInp, 0, sizeof (dataObjInp));
        rstrcpy (dataObjInp.objPath, start_dir, MAX_NAME_LEN);
        status = rcObjStat (conn, &dataObjInp, &rodsObjStatOut);
        if (status >= 0)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: found data object %s.\n", start_dir);
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
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: rclOpenCollection of %s error. status = %d", start_dir, status);
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
                parent_dir = nullptr;
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
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: calling globus_gridftp_server_finished_stat_partial\n");
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


static
void
globus_l_gfs_iRODS_read_from_net(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle);

static
void
globus_l_gfs_get_next_read_block(
        globus_off_t&                offset,
        globus_size_t&               read_length,
        globus_l_gfs_iRODS_handle_t* iRODS_handle);

static
void
globus_l_gfs_net_write_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
void
seek_and_read(
        globus_l_gfs_iRODS_handle_t *iRODS_handle,
        std::vector<read_write_buffer_t>& irods_read_buffer_vector,
        int thr_id,
        rcComm_t *conn,
        int irods_fd);
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

    err_str = globus_common_create_string("iRODS: Error: %s. %s: %s, status: %d.\n", msg, errorName, errorSubName, status);
    result = GlobusGFSErrorGeneric(err_str);
    free(err_str);
    err_str = nullptr;

    return result;
}

static
globus_bool_t
iRODS_connect_and_login(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle,
    globus_result_t&                      result,
    rcComm_t*&                            conn,
    const std::string&                    call_context_for_logging = "")
{

    result = GLOBUS_SUCCESS;

    int       status;
    rErrMsg_t errMsg;

    {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

        if (getenv(IRODS_CONNECT_AS_ADMIN)!=nullptr) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s calling _rcConnect(%s,%i,%s,%s, %s, %s)\n",
                    call_context_for_logging.c_str(), iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->adminUser, iRODS_handle->adminZone,
                    iRODS_handle->user, iRODS_handle->zone);
            conn = _rcConnect(iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->adminUser, iRODS_handle->adminZone,iRODS_handle->user,
                    iRODS_handle->zone, &errMsg, 0, 0);
        } else {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s calling rcConnect(%s,%i,%s,%s)\n", iRODS_handle->hostname,
                    call_context_for_logging.c_str(), iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone);
            conn = rcConnect(iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone, 0, &errMsg);
        }
        if (conn == nullptr) {
            char *err_str = globus_common_create_string("rcConnect failed:: %s Host: '%s', Port: '%i', UserName '%s', Zone '%s'\n",
                    errMsg.msg, iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->user, iRODS_handle->zone);
            result = GlobusGFSErrorGeneric(err_str);
            return false;
        }
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s connected now logging in.\n", call_context_for_logging.c_str());
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    status = clientLogin(conn, nullptr, NULL);
#pragma GCC diagnostic pop
    if (status != 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s logging in failed with error %d.\n", call_context_for_logging.c_str(), status);
        result = globus_l_gfs_iRODS_make_error("\'clientLogin\' failed.", status);
        return false;
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s connected.\n", call_context_for_logging.c_str());

    return true;
} // end iRODS_connect_and_login

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

    GlobusGFSName(globus_l_gfs_iRODS_start);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);

    load_client_api_plugins();

    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_gfs_finished_info_t          finished_info;

    rodsEnv myRodsEnv;
    char *user_name;
    char *homeDirPattern;
    int status;

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.username = session_info->username;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *)
        globus_malloc(sizeof(globus_l_gfs_iRODS_handle_t));

    irods::at_scope_exit cleanup_and_finalize{[op, &result, &finished_info] {

        if (result != GLOBUS_SUCCESS)
        {
            globus_gridftp_server_operation_finished(op, result, &finished_info);
        }
    }};

    if(iRODS_handle == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS: start: malloc failed");
        return;
    }
    finished_info.info.session.session_arg = iRODS_handle;

    globus_mutex_init(&iRODS_handle->mutex, nullptr);
    globus_fifo_init(&iRODS_handle->rh_q);

    status = getRodsEnv(&myRodsEnv);
    if (status >= 0) {

        // myRodsEnv is a structure on the stack, we must make explicit string copies
        iRODS_handle->hostname = strdup(myRodsEnv.rodsHost);
        iRODS_handle->port = myRodsEnv.rodsPort;
        iRODS_handle->zone = strdup(myRodsEnv.rodsZone);
        iRODS_handle->adminUser = strdup(myRodsEnv.rodsUserName);
        iRODS_handle->adminZone = strdup(myRodsEnv.rodsZone);

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
        iRODS_handle->first_write_done = false;

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

                if (iRODS_handle->zone != nullptr)
                {
                    free(iRODS_handle->zone);
                    iRODS_handle->zone = nullptr;
                }
                iRODS_handle->zone = strdup(token2);

                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: found zone '%s' in user name '%s'\n",
                        iRODS_handle->zone, iRODS_handle->user);

                if (iRODS_handle->user != nullptr)
                {
                    free(iRODS_handle->user);
                    iRODS_handle->zone = nullptr;
                }
                iRODS_handle->user = strdup(token);
            }
        }
        free(username_to_parse);
        username_to_parse = nullptr;

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: iRODS_handle->hostname = [%s] iRODS_handle->port = [%i] "
                "myRodsEnv.rodsUserName = [%s] myRodsEnv.rodsZone = [%s] iRODS_handle->user = [%s] iRODS_handle->zone = [%s]\n",
                iRODS_handle->hostname, iRODS_handle->port, iRODS_handle->adminUser, iRODS_handle->adminZone, iRODS_handle->user,
                iRODS_handle->zone);

        if (!iRODS_connect_and_login(iRODS_handle, result, iRODS_handle->conn, "main thread"))
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: main thread: failed to connect.  exiting...\n");
            return;
        }

        homeDirPattern = getenv(HOMEDIR_PATTERN);
        if (homeDirPattern == nullptr) { homeDirPattern = const_cast<char*>(DEFAULT_HOMEDIR_PATTERN); }
        finished_info.info.session.home_dir = globus_common_create_string(homeDirPattern, iRODS_handle->zone, iRODS_handle->user);
        free(user_name);
        user_name = nullptr;

        // default to 3 threads for read/write
        iRODS_handle->number_of_irods_read_write_threads = DEFAULT_NUMBER_OF_IRODS_READ_WRITE_THREADS;
        char * number_of_irods_read_write_threads_str = getenv(NUMBER_OF_IRODS_READ_WRITE_THREADS);
        if (number_of_irods_read_write_threads_str)
        {
            try
            {
                iRODS_handle->number_of_irods_read_write_threads = boost::lexical_cast<int>(number_of_irods_read_write_threads_str);

                // set a hard limit in the range [1,10]
                if (iRODS_handle->number_of_irods_read_write_threads > MAXIMUM_NUMBER_OF_IRODS_READ_WRITE_THREADS)
                {
                    iRODS_handle->number_of_irods_read_write_threads = MAXIMUM_NUMBER_OF_IRODS_READ_WRITE_THREADS;
                }

                if (iRODS_handle->number_of_irods_read_write_threads < 1)
                {
                    iRODS_handle->number_of_irods_read_write_threads = 1;
                }
            } catch ( const boost::bad_lexical_cast& ) {}
        }

        // if file size threshold is not set, it will default to 0 in which case no genquery
        // will be performed and all downloads will using number_of_irods_read_write_threads
        iRODS_handle->irods_parallel_file_size_threshold_bytes = 0L;
        char * irods_parallel_file_size_threshold_bytes_str = getenv(IRODS_PARALLEL_FILE_SIZE_THRESHOLD_BYTES);
        if (irods_parallel_file_size_threshold_bytes_str)
        {
            try
            {
                int64_t threshold = boost::lexical_cast<int64_t>(irods_parallel_file_size_threshold_bytes_str);
                if (threshold > 0)
                {
                    iRODS_handle->irods_parallel_file_size_threshold_bytes = threshold;
                }
            } catch ( const boost::bad_lexical_cast& ) {
            }
        }

        globus_gridftp_server_set_checksum_support(op, "MD5:1;SHA256:2;SHA512:3;SHA1:4;ADLER32:10;");

        globus_gridftp_server_operation_finished(op, GLOBUS_SUCCESS, &finished_info);
        globus_free(finished_info.info.session.home_dir);
        finished_info.info.session.home_dir = nullptr;
        return;
    }

    result = globus_l_gfs_iRODS_make_error("\'getRodsEnv\' failed.", status);

} // globus_l_gfs_iRODS_start

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
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;

    if (user_arg != nullptr) {

        iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
        globus_mutex_destroy(&iRODS_handle->mutex);
        globus_fifo_destroy(&iRODS_handle->rh_q);

        // Note that rcDisconnnect calls freeRcComm which calls cleanRcComm.  This
        // frees the conn pointer.
        iRODS_disconnect(iRODS_handle->conn, "main_thread");

        globus_free(iRODS_handle);
        iRODS_handle = nullptr;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s returned\n", __FUNCTION__);
} // end globus_l_gfs_iRODS_destroy

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
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusGFSName(globus_l_gfs_iRODS_stat);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);

    irods::at_scope_exit cleanup_and_finalize{[op, &result] {
        if (result != GLOBUS_SUCCESS)
        {
            globus_gridftp_server_finished_stat(op, result, nullptr, 0);
        }
    }};

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

                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: if '%s' is a PID the Handle Server '%s' will resolve it!!\n",
                        PID, handle_server);

                // Let's try to resolve the PID
                res = manage_pid(handle_server, PID, &URL);
                if (res == 0)
                {
                    // PID resolved
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: the Handle Server returned the URL: %s\n", URL);
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
                        char *err_str = globus_common_create_string("iRODS: the Handle Server '%s' returnd the URL '%s' "
                                "which is not managed by this GridFTP server which is connected through the iRODS DSI to: %s\n",
                                handle_server, URL, iRODS_handle->hostname);
                        result = GlobusGFSErrorGeneric(err_str);
                        return;
                    }
                }
                else if (res == 1)
                {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: unable to resolve the PID with the Handle Server\n");
                }
                else
                {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: unable to resolve the PID. The Handle Server "
                            "returned the response code: %i\n", res);
                }
            }
            else
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: this is not a valid PID: %s\n", stat_info->pathname);
            }
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: stat_info->pathname=%s\n", stat_info->pathname);
        if (iRODS_handle->resolved_stat_path)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: iRODS_handle->resolved_stat_path=%s\n", iRODS_handle->resolved_stat_path);
        }
    }

    status = iRODS_l_stat1(iRODS_handle->conn, &stat_buf, stat_info->pathname);
    if (status == -808000 || status == -310000)
    {
        result = globus_l_gfs_iRODS_make_error("No such file or directory.", status); //UberFTP NEEDS "No such file or directory" in error message
        return;
    }
    else if(status < 0)
    {
        result = globus_l_gfs_iRODS_make_error("iRODS_l_stat1 failed.", status);
        return;
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
        stat_buf.name = nullptr;

        // jjames - iRODS_l_stat_dir sends partial listings via globus_gridftp_server_finished_stat_partial,
        // any left over the rest will be handled below as normal
        rc = iRODS_l_stat_dir(op, iRODS_handle->conn, &stat_array, &stat_count, stat_info->pathname, iRODS_handle->user);
        if(rc != 0)
        {
            result = globus_l_gfs_iRODS_make_error("iRODS_l_stat_dir failed.", rc);
            return;
        }

    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: calling globus_gridftp_server_finished_stat\n");
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    /* gota free the names */
    for(i = 0; i < stat_count; i++)
    {
        globus_free(stat_array[i].name);
    }
    globus_free(stat_array);
    stat_array = nullptr;
    return;

} // end globus_l_gfs_iRODS_stat

extern "C"
globus_result_t globus_l_gfs_iRODS_realpath(
        const char *                        in_path,
        char **                             out_realpath,
        void *                              user_arg) {

    GlobusGFSName(globus_l_gfs_iRODS_realpath);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);

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
        result = GlobusGFSErrorGeneric("iRODS: strdup failed");
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

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: (%s) if '%s' is a PID the Handle Server '%s' will resolve it!\n",
                __FUNCTION__, PID, handle_server);

        // Let's try to resolve the PID
        res = manage_pid(handle_server, PID, &URL);
        if (res == 0)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: (%s) the Handle Server returned the URL: %s\n", __FUNCTION__, URL);
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
                char *err_str = globus_common_create_string("iRODS: (%s) the Handle Server '%s' returnd the URL '%s' which is not "
                        "managed by this GridFTP server which is connected through the iRODS DSI to: %s\n",
                        __FUNCTION__, handle_server, URL, iRODS_handle->hostname);
                result = GlobusGFSErrorGeneric(err_str);
            }
        }
        else if (res == 1)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: (%s) unable to resolve the PID with the Handle Server\n", __FUNCTION__);
        }
        else
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: (%s) unable to resolve the PID. The Handle Server returned the "
                    "response code: %i\n", __FUNCTION__, res);
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
    cksum_thread_args_t *cksum_args = (cksum_thread_args_t*)args;

    // get update interval from server, locking for "op" although not necessary right now

    pthread_mutex_lock(cksum_args->mutex);
    irods::at_scope_exit unlock_mutex{[&cksum_args] { pthread_mutex_unlock(cksum_args->mutex); }};
    while (true) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += *cksum_args->update_interval;

        // wait for the update interval or until signaled
        pthread_cond_timedwait(cksum_args->cond, cksum_args->mutex, &ts);

        if (*cksum_args->done_flag) {
            break;
        }

        // cksm not done, send update with globus_gridftp_server_intermediate_command
        char size_t_str[32];
        snprintf(size_t_str, 32, "%zu", *cksum_args->bytes_processed);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: calling globus_gridftp_server_intermediate_command with %s\n", size_t_str);
        globus_gridftp_server_intermediate_command(*cksum_args->op, GLOBUS_SUCCESS, size_t_str);
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
        result = GlobusGFSErrorGeneric("iRODS: strdup failed");
        globus_gridftp_server_finished_command(op, result, GLOBUS_NULL);
        return;
    }

    // variables used for checksum update thread
    bool checksum_update_thread_started = false;
    pthread_t update_thread;
    bool checksum_done_flag = false;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    size_t checksum_bytes_processed = 0;

    switch(cmd_info->command)
    {
        case GLOBUS_GFS_CMD_MKD:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: GLOBUS_GFS_CMD_MKD\n");
                collInp_t collCreateInp;
                memset (&collCreateInp, 0, sizeof (collCreateInp));
                rstrcpy (collCreateInp.collName, collection, MAX_NAME_LEN);
                addKeyVal (&collCreateInp.condInput, RECURSIVE_OPR__KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: rcCollCreate collection=%s\n", collection);
                status = rcCollCreate (iRODS_handle->conn, &collCreateInp);
            }
            break;

        case GLOBUS_GFS_CMD_RMD:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: GLOBUS_GFS_CMD_RMD\n");
                collInp_t rmCollInp;
                memset (&rmCollInp, 0, sizeof (rmCollInp));
                rstrcpy (rmCollInp.collName, collection, MAX_NAME_LEN);
                addKeyVal (&rmCollInp.condInput, FORCE_FLAG_KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: rcRmColl: collection=%s\n", collection);
                status = rcRmColl (iRODS_handle->conn, &rmCollInp,0);
            }
            break;

        case GLOBUS_GFS_CMD_DELE:
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: GLOBUS_GFS_CMD_DELE\n");
                dataObjInp_t dataObjInp;
                memset (&dataObjInp, 0, sizeof (dataObjInp));
                rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
                addKeyVal (&dataObjInp.condInput, FORCE_FLAG_KW, "");
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: rcDataObjUnlink: collection=%s\n", collection);
                status = rcDataObjUnlink(iRODS_handle->conn, &dataObjInp);
            }
            break;

        case GLOBUS_GFS_CMD_RNTO:
            {
                namespace fs = irods::experimental::filesystem;
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: GLOBUS_GFS_CMD_RNTO\n");

                if (cmd_info->from_pathname == nullptr)
                {
                    result = GlobusGFSErrorGeneric("iRODS: did not receive the from path");
                    break;
                }

                char * from_path = strdup(cmd_info->from_pathname);
                if (from_path == nullptr)
                {
                    result = GlobusGFSErrorGeneric("iRODS: strdup failed");
                    break;
                }
                iRODS_l_reduce_path(from_path);
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"rename from [%s] to [%s]\n", from_path, collection);

                // determine if from_path is a collection or data object
                dataObjCopyInp_t dataObjRenameInp{};
                try
                {
                    const auto object_status = fs::client::status(*iRODS_handle->conn, from_path);
                    if (fs::client::is_data_object(object_status)) {
                        dataObjRenameInp.srcDataObjInp.oprType = dataObjRenameInp.destDataObjInp.oprType = RENAME_DATA_OBJ;
                    } else if (fs::client::is_collection(object_status)) {
                        dataObjRenameInp.srcDataObjInp.oprType = dataObjRenameInp.destDataObjInp.oprType = RENAME_COLL;
                    } else {
                        // this generally won't run because a stat is done first but just in case generate an error
                        free(from_path);
                        error_str = globus_common_create_string("iRODS: rename source [%s] does not exist\n", from_path);
                        result = GlobusGFSErrorGeneric(error_str);
                        break;
                    }
                } catch (const std::exception& e) {
                    free(from_path);
                    error_str = globus_common_create_string("iRODS: exception caught while reading source file from iRODS\n", from_path);
                    result = GlobusGFSErrorGeneric(error_str);
                    break;
                }
                rstrcpy( dataObjRenameInp.destDataObjInp.objPath, collection, MAX_NAME_LEN );
                rstrcpy( dataObjRenameInp.srcDataObjInp.objPath, from_path, MAX_NAME_LEN );
                free(from_path);
                status = rcDataObjRename(iRODS_handle->conn, &dataObjRenameInp); 
            }
            break;

        case GLOBUS_GFS_CMD_CKSM:
            {
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: GLOBUS_GFS_CMD_CKSUM\n");
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: algorithm=%s\n", cmd_info->cksm_alg);
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: collection=%s\n", collection);

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
               globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: client set update_interval to %d\n", update_interval);

               if (update_interval > 0) {

                   // client requested periodic updates
                   cksum_thread_args_t cksum_args = {&checksum_done_flag, &op, &mutex, &cond, &update_interval, &checksum_bytes_processed};

                   int result;
                   if ((result = pthread_create(&update_thread, nullptr, send_cksum_updates, &cksum_args)) != 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: could not create cksum update thread so no intermediate updates "
                               "will occur [result=%d]\n", result);
                   } else {
                       checksum_update_thread_started = true;
                   }
               }

               //SELECT META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS, MIN(DATA_MODIFY_TIME) where COLL_NAME = '/tempZone/home/rods' and DATA_NAME = 'medium_file' and DATA_REPL_STATUS = '1'
               // use lowercase 'select' and 'where' to work around
               // https://github.com/irods/irods/issues/4697
               // https://github.com/irods/irods_client_globus_connector/issues/77
               std::string metadata_query_str =
                    boost::str(boost::format(
                    "select META_DATA_ATTR_VALUE, META_DATA_ATTR_UNITS, MIN(DATA_MODIFY_TIME) "
                    "where META_DATA_ATTR_NAME = '%s' AND DATA_NAME = '%s' AND COLL_NAME = '%s' AND DATA_REPL_STATUS = '1'") %
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
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: Searching for %s, value=%s, timestamp=%s, data_modify_time=%s\n",
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
                   globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: Could not get hasher for %s\n", checksum_algorithm_lower.c_str());
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
                   globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: rcDataObjOpen returned invalid file descriptor = %d\n", fd);
                   break;
               }

               char buffer_read[HASH_BUF_SZ] = {0};

               openedDataObjInp_t input{};
               input.l1descInx = fd;
               input.len = HASH_BUF_SZ;

               bytesBuf_t output{};
               output.len = input.len;
               output.buf = buffer_read;

               int length_read = 0;
               while ((length_read = rcDataObjRead(iRODS_handle->conn, &input, &output)) > 0) {

                   {
                       pthread_mutex_lock(&mutex);
                       irods::at_scope_exit unlock_mutex{[&mutex] { pthread_mutex_unlock(&mutex); }};
                       checksum_bytes_processed += length_read;
                   }

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
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: could not convert base64 to hex\n");
                       break;
                   }
                   outChksum = strdup(hex_output.c_str());
               } else if (checksum_algorithm_upper == "SHA512") {
                   status = convert_base64_to_hex_string(digest, 512, hex_output);
                   if (status < 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: could not convert base64 to hex\n");
                       break;
                   }
                   outChksum = strdup(hex_output.c_str());
               } else if (checksum_algorithm_upper == "SHA1") {
                   status = convert_base64_to_hex_string(digest, 160, hex_output);
                   if (status < 0) {
                       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: could not convert base64 to hex\n");
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
            error_str = globus_common_create_string("iRODS: Command (%s) is not implemented.", get_command_string(cmd_info->command).c_str());
            result = GlobusGFSErrorGeneric(error_str);
            break;
    }

    free(collection);
    collection = nullptr;

    if(status < 0)
    {
        error_str = globus_common_create_string("iRODS: error: status = %d", status);
        result = GlobusGFSErrorGeneric(error_str);
    }

    if (checksum_update_thread_started)
    {

        {
            pthread_mutex_lock(&mutex);
            irods::at_scope_exit unlock_mutex{[&mutex] { pthread_mutex_unlock(&mutex); }};
            checksum_done_flag = true;
            pthread_cond_signal(&cond);
        }

        if (pthread_join(update_thread, nullptr) != 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: could not join with cksum update thread.  continuing...\n");
        }
    }

    globus_gridftp_server_finished_command(op, result, outChksum);
}

void execute_writer_thread_operation(
        globus_l_gfs_iRODS_handle_t *   iRODS_handle,
        globus_gfs_operation_t          op,
        int                             thr_id,
        char *                          collection)
{
    rcComm_t * conn = nullptr;
    globus_result_t result;
    int irods_fd;

    std::stringstream write_thread_id_ss;
    write_thread_id_ss << "write thread (" << thr_id << ")";

    // connect and open the data object
    // thread 0 already has the connection and data obect opened
    if (0 == thr_id) {
        conn = iRODS_handle->conn;
        irods_fd = iRODS_handle->fd;
    }
    else
    {
        if (!iRODS_connect_and_login(iRODS_handle, result, conn, write_thread_id_ss.str())) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: thread %d: failed to connect.  exiting...\n", thr_id);
            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            iRODS_handle->cached_res = result;
            return;
        }

        // open the data object
        dataObjInp_t dataObjInp;
        memset(&dataObjInp, 0, sizeof(dataObjInp));
        rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
        dataObjInp.openFlags = O_WRONLY;

        // add the replica token
        std::string replica_token;
        {
            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            replica_token = iRODS_handle->replica_token;
        }
        addKeyVal (&dataObjInp.condInput, REPLICA_TOKEN_KW, replica_token.c_str());

        irods_fd = rcDataObjOpen (conn, &dataObjInp);

        if (irods_fd < 0) {

            char *error_str;
            error_str = globus_common_create_string("%s:%d rcDataObjOpen failed opening '%s'\n", __FILE__, __LINE__, collection);
            result = globus_l_gfs_iRODS_make_error(error_str, irods_fd);
            free(error_str);

            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            iRODS_handle->cached_res = result;

            return;
        }
    }

    // loop through reading from circular buffer
    // Exit condition: When the iRODS_handle->done flag is set and the circular buffer is empty
    // we break out of the loop
    bool exit_condition_met = false;
    while (true) {

        read_write_buffer_t write_buffer_object;

        try {

            // Do not read from circular buffer if we are done.
            //
            // Note:  In the callback we detect EOF.  The done flag is set before the
            //   buffer is put on the circular buffer.  The last thread which gets the done
            //   flag set will handle the last write.  All other threads will be waiting on this
            //   mutex and will detect the done flag and exit.  If the done flag has been detected
            //   but the circular buffer is not yet empty, threads will continue to drain the buffer.
            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

                if (irods_write_circular_buffer.is_empty() && iRODS_handle->done) {
                    break;
                }
            }

            // read from circular buffer
            // use conditional variable to make sure first write comes from thread 0 (see issue 45)
            if (thr_id != 0) {
                std::unique_lock<std::mutex> lk(first_write_mutex);
                first_write_cv.wait(lk, [&iRODS_handle](){ return iRODS_handle->first_write_done == true; });
            }

            exit_condition_met = irods_write_circular_buffer.pop_front(write_buffer_object, [&iRODS_handle] {
                    globus_mutex_lock(&iRODS_handle->mutex);
                    irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                    bool done_flag = iRODS_handle->done;
                    return irods_write_circular_buffer.is_empty() && done_flag;
            } );

            // notify all that the first write is done
            if (thr_id == 0) {
                std::unique_lock<std::mutex> lk(first_write_mutex);
                iRODS_handle->first_write_done = true;
            }
            first_write_cv.notify_all();

            if (exit_condition_met) {
                break;
            }

            openedDataObjInp_t dataObjLseekInp;
            memset (&dataObjLseekInp, 0, sizeof (dataObjLseekInp));
            dataObjLseekInp.l1descInx = irods_fd;
            fileLseekOut_t *dataObjLseekOut = nullptr;
            dataObjLseekInp.offset = write_buffer_object.offset;
            dataObjLseekInp.whence = SEEK_SET;

            int status = rcDataObjLseek(conn, &dataObjLseekInp, &dataObjLseekOut);
            if (dataObjLseekOut) {
                std::free(dataObjLseekOut);
            }

            // verify that it worked
            if(status < 0)
            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                iRODS_handle->cached_res = globus_l_gfs_iRODS_make_error("rcDataObjLseek failed", status);
                iRODS_handle->done = GLOBUS_TRUE;
            }
            else
            {
               openedDataObjInp_t dataObjWriteInp;
               memset (&dataObjWriteInp, 0, sizeof (dataObjWriteInp));
               dataObjWriteInp.l1descInx = irods_fd;
               dataObjWriteInp.len = write_buffer_object.nbytes;

               bytesBuf_t dataObjWriteInpBBuf;
               dataObjWriteInpBBuf.buf = write_buffer_object.buffer;
               dataObjWriteInpBBuf.len = write_buffer_object.nbytes;

               int bytes_written  = rcDataObjWrite(conn, &dataObjWriteInp, &dataObjWriteInpBBuf);
               if (bytes_written < dataObjWriteInp.len) {
                   // erroring on any short write instead of only bytes_written < 0
                   globus_mutex_lock(&iRODS_handle->mutex);
                   irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                   iRODS_handle->cached_res = globus_l_gfs_iRODS_make_error("rcDataObjWrite failed", bytes_written);
                   iRODS_handle->done = GLOBUS_TRUE;
               } else {
                   globus_gridftp_server_update_bytes_written(op, write_buffer_object.offset, bytes_written);
               }
            }

            globus_free(write_buffer_object.buffer);
            write_buffer_object.buffer = nullptr;

        } catch (irods::experimental::timeout_exception& e) {
            char * err_str = globus_common_create_string("iRODS: Error: Timeout reading from buffer.\n");
            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                iRODS_handle->cached_res = GlobusGFSErrorGeneric(err_str);
                iRODS_handle->done = GLOBUS_TRUE;
            }
            free(err_str);
            break;

        }
    }

    // close the object and disconnect, thread 0 will close elsewhere
    if (thr_id != 0) {
       nlohmann::json json_input{{"fd", irods_fd}};
       json_input["update_size"] = false;
       json_input["update_status"] = false;
       json_input["preserve_replica_state_table"] = false;
       const auto json_string = json_input.dump();
       rc_replica_close(conn, json_string.c_str());
       iRODS_disconnect(conn, write_thread_id_ss.str());
   }
}

/*************************************************************************
 *  recv
 *  ----
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 *  To receive a file the following functions will be used in
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_read();
 *      globus_gridftp_server_finished_transfer();
 *
 *  Overview of flow:
 *
 *     - Call globus_gridftp_server_begin_transfer().
 *
 *     - Start N threads that loops until finished doing the following:
 *       - Reads a {buffer,nbytes,offset} pair from a circular buffer
 *       - Seeks to offset.
 *       - Writes nbytes from buffer to IRODS.
 *       - Terminate when the circular buffer is empty and the done flag is set.
 *
 *     - (A) Call globus_gridftp_server_register_read() optimal_count times
 *       incrementing the outstanding counter for each.
 *
 *        - The callback for each:
 *          - Puts its {buffer,nbytes,offset} on the circular buffer.
 *          - Decrements outstanding counter.
 *          - Sets the done flag when reading is finished.
 *          - (B) Calls globus_gridftp_server_register_read()
 *            (optimal_count - oustanding) times to make sure there are
 *            always optimal_count callbacks waiting. Increment outstanding
 *            counter for each.
 *
 *     - When finished, wait for N threads terminate and call
 *       globus_gridftp_server_finished_transfer().
 *
 *     Note that (A) and (B) are performed in
 *     globus_l_gfs_iRODS_read_from_net().
 *
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_iRODS_recv);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);

    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    int                                 flags = O_WRONLY | O_CREAT;
    char *                              collection = nullptr;
    //char *                              handle_server;
    dataObjInp_t                        dataObjInp;
    int result;

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    
    collection = strdup(transfer_info->pathname);
    iRODS_l_reduce_path(collection);

    irods::at_scope_exit free_collection{[&collection] {
        std::free(collection);
        collection = nullptr;
    }};

    // start N threads to write to file
    int number_of_irods_write_threads = iRODS_handle->number_of_irods_read_write_threads;
  
    // Make a decision about the number of write threads based on the file size provided
    // to us (transfer_info->alloc_size). Keep the number of write threads as it is unless
    // the following conditions are met:
    // 1. The transfer_info->alloc_size is defined (not zero) and greater than zero.
    // 2. The alloc_size < irods_parallel_file_size_threshold_bytes.
    // 3. Issue 101 - If filename has apostrophe then force one thread.
    //    Note: Forcing one thread will be backed out when GenQuery is fixed.  See #104 and irods/irods#3902.
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: Alloc size: %lld.\n", transfer_info->alloc_size);
    if (transfer_info->alloc_size > 0)
    {
        // Get the parallel transfer threshold.  For uploads, if this is not defined default it to 32 MiB.
        uint64_t parallel_transfer_threshold =  iRODS_handle->irods_parallel_file_size_threshold_bytes;
        if (parallel_transfer_threshold != 0)
        {
            parallel_transfer_threshold = 32*1024*1024;
        }
        if (transfer_info->alloc_size < static_cast<globus_off_t>(parallel_transfer_threshold))
        {
            number_of_irods_write_threads = 1;
        }
    }

    // Filename has an apostrophe. Due to GenQuery bug open with replica token fails. Force one write thread.
    if (strchr(collection, '\'') != nullptr) {
        number_of_irods_write_threads = 1;
    }

    result = globus_gridftp_server_get_recv_modification_time(op, &iRODS_handle->utime);
    if(result != GLOBUS_SUCCESS)
    {
        // continue but don't modify utime
        globus_gfs_log_result(GLOBUS_GFS_LOG_WARN, "iRODS: Error getting modtime, skipping: ", result);
        iRODS_handle->utime = -1;
    }
    else
    {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: globus_gridftp_server_get_recv_modification_time returned %lld.\n", static_cast<long long>(iRODS_handle->utime));
    }

    // the main thread is the first writer so thread_pool starts number_of_irods_write_threads-1 threads
    irods::thread_pool threads{number_of_irods_write_threads-1};

    {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

        if(transfer_info->pathname == nullptr)
        {
            result = GlobusGFSErrorGeneric("iRODS: transfer_info->pathname == nullptr");
            globus_gridftp_server_finished_transfer(op, result);
            return;
        }

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
            globus_gridftp_server_finished_transfer(op, result);
            return;
        }

        if(transfer_info->truncate)
        {
            flags |= O_TRUNC;
        }

        memset (&dataObjInp, 0, sizeof (dataObjInp));
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
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: Open object: %s.\n", collection);

            // get and save the replica access token
            const auto j_in = nlohmann::json{{"fd", iRODS_handle->fd}}.dump();

            char* j_out{};
            irods::at_scope_exit clean_up_j_out{[&j_out] { 
                if (j_out) {
                    std::free(j_out);
                }
            }};

            nlohmann::json fd_info;

            const auto ec = rc_get_file_descriptor_info(iRODS_handle->conn, j_in.data(), &j_out);

            if (ec != 0) {
                char *error_str;
                error_str = globus_common_create_string("Failed to retrieve remote L1 descriptor information from iRODS, error_code = %d\n", ec);
                result = globus_l_gfs_iRODS_make_error(error_str, ec);
                std::free(error_str);
                error_str = nullptr;
                globus_gridftp_server_finished_transfer(op, result);
                return;
            }

            fd_info = nlohmann::json::parse(j_out);
            std::string replica_token = fd_info.at("replica_token").get<std::string>();
            iRODS_handle->replica_token = strdup(replica_token.c_str());
        }
        else
        {
            result = globus_l_gfs_iRODS_make_error("rcDataObjOpen failed", iRODS_handle->fd);
            globus_gridftp_server_finished_transfer(op, result);
            return;
        }

        /* reset all the needed variables in the handle */

        iRODS_handle->cached_res = GLOBUS_SUCCESS;
        iRODS_handle->outstanding = 0;
        iRODS_handle->done = GLOBUS_FALSE;
        iRODS_handle->blk_length = 0;
        iRODS_handle->blk_offset = 0;
        iRODS_handle->op = op;
        globus_gridftp_server_get_block_size(
            op, &iRODS_handle->block_size);
    }

    globus_gridftp_server_begin_transfer(op, 0, iRODS_handle);

    // start number_of_irods_write_threads-1 threads to read from circular buffer and write to iRODS
    // the main thread also writes to bring us to number_of_irods_write_threads threads
    for (int thr_id = 1; thr_id < number_of_irods_write_threads; ++thr_id)
    {
        irods::thread_pool::post(threads, [&iRODS_handle, op, thr_id, collection] () {
            execute_writer_thread_operation(iRODS_handle, op, thr_id, collection);
        });
    }

    irods::thread_pool read_from_net_thread{1};
    irods::thread_pool::post(read_from_net_thread, [&iRODS_handle] () {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
        globus_l_gfs_iRODS_read_from_net(iRODS_handle);
    });

    // current thread is thread 0
    execute_writer_thread_operation(iRODS_handle, op, 0, collection);

    read_from_net_thread.join();
    threads.join();

    // close the data object
    openedDataObjInp_t dataObjCloseInp;
    memset (&dataObjCloseInp, 0, sizeof (dataObjCloseInp));
    dataObjCloseInp.l1descInx = iRODS_handle->fd;
    rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);
    
    // update the modify time if preservation option selected
    if (iRODS_handle->utime > 0)
    {
        nlohmann::json json_input;
        json_input["logical_path"] = collection;
        json_input["options"]["no_create"] = true;
        json_input["options"]["seconds_since_epoch"] = iRODS_handle->utime;
        if (const auto ec = rc_touch(iRODS_handle->conn, json_input.dump().c_str()); ec < 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                    "iRODS: Caught error (%d) trying to update the modify time for [%s]. Continuing without updating modify time.\n", ec, collection);
        }
    }

    globus_gridftp_server_finished_transfer(iRODS_handle->op, iRODS_handle->cached_res);

} // globus_l_gfs_iRODS_recv

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 *  Overview of flow:
 *
 *     - Call globus_gridftp_server_begin_transfer().
 *
 *     - Connect to iRODS N times and open the data object N times.  Both of these
 *       are stored in a vector.
 *
 *     - Loop until done:
 *
 *         - Call globus_l_gfs_get_next_read_block() N times to get offset, length
 *           for next N reads and push these onto a vector.
 *
 *         - N threads (including main thread) each read its offset and length from the vector
 *           and reads data from iRODS.
 *
 *         - Main thread waits for other N-1 reads to finish.
 *
 *         - Main thread loops through N times and calls globus_gridftp_server_register_write() and
 *           increments callback counter.
 *             - Callback for globus_gridftp_server_register_write decrements this counter and sets
 *               done flag when necessary.
 *
 *     - Terminate N threads.
 *
 *     - Wait for callback counter to be zero.
 *
 *     - Call globus_gridftp_server_finished_transfer() and cleanup (close connections and data objects).
 *
 ************************************************************************/
extern "C"
void
globus_l_gfs_iRODS_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: %s called\n", __FUNCTION__);

    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    char *                              handle_server;
    globus_result_t                     result;
    char *                              collection = nullptr;

    int                                 res = -1;
    char *                              URL;
    dataObjInp_t                        dataObjInp;

    GlobusGFSName(globus_l_gfs_iRODS_send);

    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    if(iRODS_handle == nullptr)
    {
        /* dont want to allow clear text so error out here */
        result = GlobusGFSErrorGeneric("iRODS DSI must be a default backend module. It cannot be an eret alone");
        globus_gridftp_server_finished_transfer(op, result);
        return;
    }

    collection = strdup(transfer_info->pathname);
    if(collection == nullptr)
    {
        result = GlobusGFSErrorGeneric("iRODS: strdup failed");
        globus_gridftp_server_finished_transfer(op, result);
        return;
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

            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: if '%s' is a PID the Handle Server '%s' will resolve it!\n", PID, handle_server);

            // Let's try to resolve the PID
            res = manage_pid(handle_server, PID, &URL);
            if (res == 0)
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: the Handle Server returned the URL: %s\n", URL);
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
                    char *err_str = globus_common_create_string("iRODS: the Handle Server '%s' returnd the URL '%s' "
                            "which is not managed by this GridFTP server which is connected through the iRODS DSI to: %s\n",
                            handle_server, URL, iRODS_handle->hostname);

                    result = GlobusGFSErrorGeneric(err_str);
                    globus_free(collection);
                    globus_gridftp_server_finished_transfer(op, result);
                    return;
                }
            }
            else if (res == 1)
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: unable to resolve the PID with the Handle Server\n");
            }
            else
            {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: unable to resolve the PID. The Handle Server returned the "
                        "response code: %i\n", res);
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

    int optimal_count = iRODS_handle->optimal_count;

    // set up N threads to read from iRODS
    // if N=1 then only the main thread will be active
    int number_of_irods_read_threads = iRODS_handle->number_of_irods_read_write_threads;
    irods::thread_pool irods_read_threads{number_of_irods_read_threads};

    // get the file size from iRODS genquery to make a better decision about # threads
    // if the threshold is zero, do not do query and just use the number_of_irods_read_threads
    if (iRODS_handle->irods_parallel_file_size_threshold_bytes != 0)
    {
        std::string logical_path{collection};

        try
        {
            uintmax_t data_size = irods::experimental::filesystem::client::data_object_size(*(iRODS_handle->conn), logical_path);

            if (data_size < iRODS_handle->irods_parallel_file_size_threshold_bytes)
            {
                // override the number of read threads
                number_of_irods_read_threads = 1;
            }

        } catch (...) {} // keep number of read threads as is

    }

    // create a vector for the thread connections
    std::vector<rcComm_t*> conn_vector(number_of_irods_read_threads);
    std::vector<int> fd_vector(number_of_irods_read_threads);

    globus_gridftp_server_begin_transfer(op, 0, iRODS_handle);

    // cleanup at scope exit
    irods::at_scope_exit cleanup_and_finalize{[&iRODS_handle, &conn_vector, &fd_vector, op, collection, number_of_irods_read_threads] {

        // close the replicas, main thread closes at destroy()
        for (int thr_id = 1; thr_id < number_of_irods_read_threads; ++thr_id)
        {
            if (conn_vector[thr_id])
            {
                std::stringstream irods_read_thread_ss;
                irods_read_thread_ss << "irods read thread (" << thr_id << ")";

                // close the object and disconnect this thread from iRODS
                nlohmann::json json_input{{"fd", fd_vector[thr_id]}};
                json_input["update_size"] = false;
                json_input["update_status"] = false;
                json_input["preserve_replica_state_table"] = false;
                const auto json_string = json_input.dump();
                rc_replica_close(conn_vector[thr_id], json_string.c_str());

                iRODS_disconnect(conn_vector[thr_id], irods_read_thread_ss.str());
            }
        }

        globus_result_t result;
        globus_mutex_lock(&iRODS_handle->mutex);
        result = iRODS_handle->cached_res;
        globus_mutex_unlock(&iRODS_handle->mutex);

        globus_gridftp_server_finished_transfer(op, result);

        if (collection)
        {
            globus_free(collection);
        }

    }};

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: retrieving '%s'\n", collection);
    memset(&dataObjInp, 0, sizeof (dataObjInp));
    rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
    dataObjInp.openFlags = O_RDONLY;

    // give priority to explicit resource mapping, otherwise use default resource if set
    if (iRODS_Resource_struct.resource != nullptr)
    {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_Resource_struct.resource);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: retrieving object with resource: %s\n", iRODS_Resource_struct.resource);
    }
    else if (iRODS_handle->defResource != nullptr ) {
        addKeyVal (&dataObjInp.condInput, RESC_NAME_KW, iRODS_handle->defResource);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"iRODS: retrieving object from default resource: %s\n", iRODS_handle->defResource);
    };

    // main thread open the data object, all others will open with the replica access token
    iRODS_handle->fd = rcDataObjOpen (iRODS_handle->conn, &dataObjInp);
    if (iRODS_handle->fd < 3) {

        globus_mutex_lock(&iRODS_handle->mutex);

        char *error_str;
        error_str = globus_common_create_string("rcDataObjOpen returned an invalid file descriptor = %d\n", iRODS_handle->fd);
        iRODS_handle->cached_res = globus_l_gfs_iRODS_make_error(error_str, iRODS_handle->fd);
        free(error_str);
        iRODS_handle->done = true;

        globus_mutex_unlock(&iRODS_handle->mutex);

        return;
    }

    // populate conn_vector[0] and fd_vector[0] with main thread info
    conn_vector[0] = iRODS_handle->conn;
    fd_vector[0] = iRODS_handle->fd;

    // create N-1 connections and open file N times
    for (int thr_id = 1; thr_id < number_of_irods_read_threads; ++thr_id)
    {
        globus_result_t result;

        std::stringstream irods_read_thread_ss;
        irods_read_thread_ss << "irods read thread (" << thr_id << ")";

        if (!iRODS_connect_and_login(iRODS_handle, result, conn_vector[thr_id], irods_read_thread_ss.str()))
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: thread %d: failed to connect.  exiting...\n", thr_id);
            iRODS_handle->done = true;

            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            iRODS_handle->cached_res = result;
            return;
        }

        dataObjInp_t dataObjInp{};
        dataObjInp.openFlags = O_RDONLY;
        rstrcpy (dataObjInp.objPath, collection, MAX_NAME_LEN);
        fd_vector[thr_id] = rcDataObjOpen(conn_vector[thr_id], &dataObjInp);

        if (fd_vector[thr_id] < 0)
        {
            char *error_str;
            if (handle_server != nullptr)
                if (res == 0) {
                    error_str = globus_common_create_string("%s:%d rcDataObjOpen failed opening '%s' (the DSI has succesfully resolved the PID "
                            "through the Handle Server '%s.)", __FILE__, __LINE__, collection, handle_server);
                }
                else
                {
                    error_str = globus_common_create_string("%s:%d rcDataObjOpen failed opening '%s' (the DSI has also tried to manage the path "
                            "as a PID but the resolution through the Handle Server '%s' failed)", __FILE__, __LINE__, collection, handle_server);
                }
            else
            {
                error_str = globus_common_create_string("%s:%d rcDataObjOpen failed opening '%s'\n", __FILE__, __LINE__, collection);
            }
            result = globus_l_gfs_iRODS_make_error(error_str, iRODS_handle->fd);
            free(error_str);
            error_str = nullptr;
            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                iRODS_handle->done = true;
                iRODS_handle->cached_res = result;
            }
        }
    }

    if (iRODS_handle->cached_res != GLOBUS_SUCCESS)
    {
        return;
    }

    std::vector<read_write_buffer_t> irods_read_buffer_vector;

    std::condition_variable task_done_cv;
    std::mutex task_done_mutex;

    // keep reading from iRODS until the done flag is set
    while (true)
    {

        // to keep track of read task completions
        int task_done_cntr = 0;

        // read the next N offsets
        for (int i = 0; i < number_of_irods_read_threads; ++i)
        {
            globus_off_t offset;
            globus_size_t read_length;
            globus_l_gfs_get_next_read_block(offset, read_length, iRODS_handle);
            irods_read_buffer_vector.push_back({nullptr, read_length, offset});
        }

        // each thread seeks to offset and reads their buffer (main thread is thr_id 0)
        for (int thr_id = 1; thr_id < number_of_irods_read_threads; ++thr_id)
        {

            // conn_vector and fd_vector do not have main thread's
            rcComm_t * conn = conn_vector[thr_id];
            int irods_fd = fd_vector[thr_id];

            irods::thread_pool::post(irods_read_threads, [&iRODS_handle, &irods_read_buffer_vector, &task_done_mutex,
                    &task_done_cntr, &task_done_cv, conn, irods_fd, thr_id] ()
            {

                seek_and_read(iRODS_handle, irods_read_buffer_vector, thr_id, conn, irods_fd);

                {
                    std::lock_guard<std::mutex> lk(task_done_mutex);
                    task_done_cntr++;
                }
                task_done_cv.notify_all();
            });
        }

        // main thread also seeks and reads
        seek_and_read(iRODS_handle, irods_read_buffer_vector, 0, conn_vector[0], fd_vector[0]);

        // wait for all tasks to be completed (main thread is already done and doesn't increment task_done_cntr
        std::unique_lock<std::mutex> lk(task_done_mutex);
        task_done_cv.wait(lk, [&task_done_cntr, number_of_irods_read_threads]() { return task_done_cntr == number_of_irods_read_threads - 1; });

        // break if done or an error occurred
        {
            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            if (iRODS_handle->cached_res != GLOBUS_SUCCESS)
            {
                break;
            }
        }

        // grab all buffers and send to globus_gridftp_server_register_write
        for (int i = 0; i < number_of_irods_read_threads; ++i)
        {

            // grab the buffer object, copy to globus_l_iRODS_read_ahead_t and send to register_write
            globus_l_iRODS_read_ahead_t *read_ahead_buffer = (globus_l_iRODS_read_ahead_t*)globus_malloc(sizeof(globus_l_iRODS_read_ahead_t));
            if (read_ahead_buffer == nullptr)
            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

                iRODS_handle->cached_res = GlobusGFSErrorGeneric("malloc failed");
                break;
            }

            read_write_buffer_t& buffer_object = irods_read_buffer_vector[i];

            if (buffer_object.nbytes > 0 && buffer_object.buffer != nullptr)
            {
                read_ahead_buffer->iRODS_handle = iRODS_handle;
                read_ahead_buffer->offset = buffer_object.offset;
                read_ahead_buffer->length = buffer_object.nbytes;
                read_ahead_buffer->buffer = buffer_object.buffer;

                globus_result_t res;

                // wait until there are less than optimal_count outstanding callbacks
                using namespace std::chrono_literals;
                auto now = std::chrono::system_clock::now();
                std::unique_lock<std::mutex> lk(outstanding_cntr_mutex);

                // wait until the number of outstanding is less than optimal_count so as to not
                // having too many outstanding callbacks
                if (!outstanding_cntr_cv.wait_until(lk, now + 30s, [&iRODS_handle, optimal_count](){ return iRODS_handle->outstanding < optimal_count; }))
                {
                    char * err_str;
                    err_str = globus_common_create_string("iRODS: Error: timeout waiting for callbacks to free before "
                            "sending to globus_gridftp_server_register_write.\n");

                    iRODS_handle->cached_res = GlobusGFSErrorGeneric(err_str);
                    free(err_str);
                }

                res = globus_gridftp_server_register_write(
                    iRODS_handle->op, buffer_object.buffer, buffer_object.nbytes, buffer_object.offset, -1,
                    globus_l_gfs_net_write_cb, read_ahead_buffer);

                if (res != GLOBUS_SUCCESS)
                {

                    globus_mutex_lock(&iRODS_handle->mutex);
                    irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

                    iRODS_handle->cached_res = res;
                    break;
                }

                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                iRODS_handle->outstanding++;

            }
        }

        // break if done or an error occurred
        {
            globus_mutex_lock(&iRODS_handle->mutex);
            irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
            if (iRODS_handle->done || iRODS_handle->cached_res != GLOBUS_SUCCESS)
            {
                break;
            }
        }

        irods_read_buffer_vector.clear();

    } // end while (true)

    // wait for callbacks to complete
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: waiting for callbacks to complete\n");
    using namespace std::chrono_literals;
    auto now = std::chrono::system_clock::now();
    std::unique_lock<std::mutex> lk(outstanding_cntr_mutex);
    if (!outstanding_cntr_cv.wait_until(lk, now + 30s, [&iRODS_handle](){ return iRODS_handle->outstanding == 0; }))
    {
        char * err_str;
        err_str = globus_common_create_string("iRODS: Error: timeout waiting for callbacks to finish.\n");
        iRODS_handle->cached_res = GlobusGFSErrorGeneric(err_str);
        free(err_str);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: callbacks completed\n");

    // close the data object
    openedDataObjInp_t dataObjCloseInp;
    memset (&dataObjCloseInp, 0, sizeof (dataObjCloseInp));
    dataObjCloseInp.l1descInx = iRODS_handle->fd;
    rcDataObjClose(iRODS_handle->conn, &dataObjCloseInp);

    return;

} // end globus_l_gfs_iRODS_send

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
    globus_l_gfs_iRODS_handle_t *       iRODS_handle;
    //int                                 bytes_written;


    iRODS_handle = (globus_l_gfs_iRODS_handle_t *) user_arg;
    if(eof)
    {
        iRODS_handle->done = GLOBUS_TRUE;
    }

    /* if the read was successful write to circular buffer*/
    if (nbytes > 0)
    {

        try {

            // write to circular buffer - done flags are set in the post-push lambda to avoid
            // race conditions
            irods_write_circular_buffer.push_back({buffer, nbytes, offset }, [&iRODS_handle, &result] {

                    {
                        globus_mutex_lock(&iRODS_handle->mutex);
                        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                        iRODS_handle->outstanding--;
                        if(result != GLOBUS_SUCCESS)
                        {
                            iRODS_handle->cached_res = result;
                            iRODS_handle->done = GLOBUS_TRUE;
                        }
                    }


                });  // circular buffer reader handles the done flag

            // don't free buffer as it is used by threads reading the circular buffer

        } catch (irods::experimental::timeout_exception& e) {
            char * err_str;
            GlobusGFSName(__FUNCTION__);
            err_str = globus_common_create_string("iRODS: Error: timeout waiting to write to buffer.\n");

            {
                globus_mutex_lock(&iRODS_handle->mutex);
                irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
                iRODS_handle->cached_res = GlobusGFSErrorGeneric(err_str);
                iRODS_handle->done = GLOBUS_TRUE;
            }

            free(err_str);

        }
    }

    {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

        // if not done call globus_l_gfs_iRODS_read_from_net to handle more
        if(!iRODS_handle->done)
        {
            globus_l_gfs_iRODS_read_from_net(iRODS_handle);
        }
    }

} // end globus_l_gfs_iRODS_net_read_cb

// reads data from the client and populates the circular buffer
// precondition: iRODS_handle mutex is already locked
static
void
globus_l_gfs_iRODS_read_from_net(
    globus_l_gfs_iRODS_handle_t *         iRODS_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     result = GLOBUS_SUCCESS;
    GlobusGFSName(globus_l_gfs_iRODS_read_from_net);

    irods::at_scope_exit cleanup_and_finalize{[&iRODS_handle, &result] {
        if (result != GLOBUS_SUCCESS)
        {
            iRODS_handle->cached_res = result;
            iRODS_handle->done = GLOBUS_TRUE;
        }
    }};

    /* in the read case this number will vary */
    globus_gridftp_server_get_optimal_concurrency(
        iRODS_handle->op, &iRODS_handle->optimal_count);

    // each time this runs, start up optimal_count - outstanding registers
    while(iRODS_handle->outstanding < iRODS_handle->optimal_count)
    {
        buffer = static_cast<unsigned char*>(globus_malloc(iRODS_handle->block_size));
        if (buffer == nullptr)
        {
            result = GlobusGFSErrorGeneric("malloc failed");
            return;
        }
        result = globus_gridftp_server_register_read(
            iRODS_handle->op,
            buffer,
            iRODS_handle->block_size,
            globus_l_gfs_iRODS_net_read_cb,
            iRODS_handle);
        if (result != GLOBUS_SUCCESS)
        {
            return;
        }
        iRODS_handle->outstanding++;
    }

    return;

} // end globus_l_gfs_iRODS_read_from_net

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
    globus_l_iRODS_read_ahead_t * rh = (globus_l_iRODS_read_ahead_t *) user_arg;
    if (rh == nullptr)
    {
        // should not happen, recovery path is a timeout waiting on callbacks to complete
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: (%s) rh is null\n", __FUNCTION__);
        return;
    }

    globus_l_gfs_iRODS_handle_t * iRODS_handle = rh->iRODS_handle;
    if (iRODS_handle == nullptr)
    {
        // should not happen, recovery path is a timeout waiting on callbacks to complete
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: (%s) rh is null\n", __FUNCTION__);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "iRODS: (%s) iRODS_handle is null\n", __FUNCTION__);
        return;
    }

    {
        // decrement outstanding callback counter
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
        iRODS_handle->outstanding--;
    }
    outstanding_cntr_cv.notify_all();

    if (result != GLOBUS_SUCCESS)
    {
        // set done flag
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
        iRODS_handle->cached_res = result;
        iRODS_handle->done = GLOBUS_TRUE;
    }

    if (rh->buffer)
    {
        free(rh->buffer);
    }
    globus_free(rh);
}

static
void
seek_and_read(
        globus_l_gfs_iRODS_handle_t *iRODS_handle,
        std::vector<read_write_buffer_t>& irods_read_buffer_vector,
        int thr_id,
        rcComm_t *conn,
        int irods_fd) {

    openedDataObjInp_t dataObjLseekInp;
    memset (&dataObjLseekInp, 0, sizeof (dataObjLseekInp));
    dataObjLseekInp.l1descInx = irods_fd;
    dataObjLseekInp.offset = static_cast<long>(irods_read_buffer_vector[thr_id].offset);
    dataObjLseekInp.whence = SEEK_SET;
    fileLseekOut_t *dataObjLseekOut = nullptr;

    int status = rcDataObjLseek(conn, &dataObjLseekInp, &dataObjLseekOut);
    if (dataObjLseekOut) {
        std::free(dataObjLseekOut);
    }

    // verify that it worked
    if (status < 0)
    {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};
        iRODS_handle->done = GLOBUS_TRUE;
    } else {

        openedDataObjInp_t dataObjReadInp;
        memset (&dataObjReadInp, 0, sizeof (dataObjReadInp));
        dataObjReadInp.l1descInx = irods_fd;
        dataObjReadInp.len = irods_read_buffer_vector[thr_id].nbytes;

        bytesBuf_t dataObjReadOutBBuf;
        memset (&dataObjReadOutBBuf, 0, sizeof (dataObjReadOutBBuf));

        auto nbytes = rcDataObjRead (conn, &dataObjReadInp, &dataObjReadOutBBuf);

        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

        if (nbytes > 0)
        {
            irods_read_buffer_vector[thr_id].buffer = static_cast<globus_byte_t *>(dataObjReadOutBBuf.buf);
            irods_read_buffer_vector[thr_id].nbytes = nbytes;
        } else {
            irods_read_buffer_vector[thr_id].buffer = nullptr;
            irods_read_buffer_vector[thr_id].nbytes = 0;
            iRODS_handle->done = GLOBUS_TRUE;
        }
    }
}

// returns true if done
static
void
globus_l_gfs_get_next_read_block(
        globus_off_t&                offset,
        globus_size_t&               read_length,
        globus_l_gfs_iRODS_handle_t* iRODS_handle)
{
    GlobusGFSName(globus_l_gfs_get_next_read_block);
    {
        globus_mutex_lock(&iRODS_handle->mutex);
        irods::at_scope_exit unlock_mutex{[&iRODS_handle] { globus_mutex_unlock(&iRODS_handle->mutex); }};

        /* if we have done everything for this block, get the next block
           also this will happen the first time
           -1 length means until the end of the file  */
        if(iRODS_handle->blk_length == 0)
        {
            // check the next range to read
            // returns a length of 0 when done
            globus_gridftp_server_get_read_range(
                iRODS_handle->op,
                &iRODS_handle->blk_offset,
                &iRODS_handle->blk_length);

            if(iRODS_handle->blk_length == 0)
            {
                iRODS_handle->read_eof = GLOBUS_TRUE;
            }
        }

        /* get the current length to read */
        if(iRODS_handle->blk_length == -1 || iRODS_handle->blk_length > static_cast<globus_off_t>(iRODS_handle->block_size))
        {
            read_length = (int)iRODS_handle->block_size;
        } else {
            read_length = (int)iRODS_handle->blk_length;
        }

        offset = iRODS_handle->blk_offset;

        // for the next thread/pass
        iRODS_handle->blk_offset += read_length;
        if(iRODS_handle->blk_length != -1)
        {
            iRODS_handle->blk_length -= read_length;
        }

    }
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
