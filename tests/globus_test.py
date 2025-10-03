from unittest import *
import inspect
import os
try:
    import telnetlib
except:
    import telnetlib3 as telnetlib

import hashlib
import zlib
from libs.execute import *
from libs.command import *
from libs.utility import *
from datetime import datetime
from ftplib import FTP, error_perm

def get_telnet_checksum_command(checksum_type, filename):
    cksm_command = bytearray(b'cksm ')
    cksm_command.extend(checksum_type.encode())
    cksm_command.extend(b' 0 1 ')
    cksm_command.extend(filename.encode())
    cksm_command.extend(b'\r\n')
    return cksm_command

# convert the response (example b'213 77de104b6b11b23d4a6f22adb044884c\r\n') to
# a string and grab only the checksum
def parse_telnet_checksum_response_as_string(response):
    return response.decode('utf-8').split(' ')[1].splitlines()[0]

def change_user_gridftp_mapfile(old_user, new_user):
    with open('/etc/grid-security/grid-mapfile', 'r+') as f:
        contents = f.read()
    new_contents = re.sub(f'{old_user}$', new_user, contents)
    with open('/etc/grid-security/grid-mapfile', 'w') as f:
          f.write(new_contents)

class Globus_Test(TestCase):

    hostname = os.environ["HOSTNAME"] 

    def __init__(self, *args, **kwargs):
        super(Globus_Test, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_resource_mapfile(self):
        # the resource mapfile was already set up by the docker scripts
        put_filename = inspect.currentframe().f_code.co_name 

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'imkdir /tempZone/home/rods/dir1 /tempZone/home/rods/dir2')
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/')
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/dir1/')
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/dir2/')

            # files in /tempZone/home/rods should go to the default resource 
            assert_command(f'ils -l /tempZone/home/rods/{put_filename}', 'STDOUT_SINGLELINE', 'demoResc')

            # files in /tempZone/home/rods/dir1 should go to resc1 according to resource mapfile
            assert_command(f'ils -l /tempZone/home/rods/dir1/{put_filename}', 'STDOUT_SINGLELINE', 'resc1')

            # files in /tempZone/home/rods/dir2 should go to resc2 according to resource mapfile
            assert_command(f'ils -l /tempZone/home/rods/dir2/{put_filename}', 'STDOUT_SINGLELINE', 'resc2')

        finally:
            os.remove(put_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')
            assert_command(f'irm -rf /tempZone/home/rods/dir1')
            assert_command(f'irm -rf /tempZone/home/rods/dir2')

    def test_upload_small_file_with_globus_url_copy(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/')
            assert_command(f'iget /tempZone/home/rods/{put_filename} {get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')

    def test_upload_large_file_with_globus_url_copy(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024*1024)
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/')
            assert_command(f'iget /tempZone/home/rods/{put_filename} {get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')

    def test_upload_large_file_with_apostrophe_in_filename_with_globus_url_copy__issue_101(self):
        put_filename = f'{inspect.currentframe().f_code.co_name}\'s file'
        get_filename = f'{put_filename}.get'

        try:

            make_arbitrary_file(put_filename, 100*1024*1024)
            assert_command(f'globus-url-copy "{put_filename}" "gsiftp://{self.hostname}:2811/tempZone/home/rods/{put_filename}"')
            assert_command(f'iget "/tempZone/home/rods/{put_filename}" "{get_filename}"')
            assert_command(f'diff -q "{put_filename}" "{get_filename}"')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f "/tempZone/home/rods/{put_filename}"')

    def test_upload_and_download_file_with_globus_url_copy_as_non_privileged_user(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:
            change_user_gridftp_mapfile('rods', 'user1')
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/user1/')
            assert_command(f'globus-url-copy gsiftp://{self.hostname}:2811/tempZone/home/user1/{put_filename} {get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            #TODO issue 97 - when able to run icommand as other users remove file
            #assert_command(f'irm -f /tempZone/home/user1/{put_filename}')
            change_user_gridftp_mapfile('user1', 'rods')

    def test_download_small_file_with_globus_url_copy(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} /tempZone/home/rods/')
            assert_command(f'globus-url-copy gsiftp://{self.hostname}:2811/tempZone/home/rods/{put_filename} {get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')

    def test_download_large_file_with_globus_url_copy(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024*1024)
            assert_command(f'iput {put_filename} /tempZone/home/rods/')
            assert_command(f'globus-url-copy gsiftp://{self.hostname}:2811/tempZone/home/rods/{put_filename} {get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')

    def test_copy_from_irods_to_irods_with_globus_url_copy(self):
        put_filename = inspect.currentframe().f_code.co_name 
        get_filename = f'{put_filename}.get'

        try:
            make_arbitrary_file(put_filename, 100*1024)
            assert_command(f'iput {put_filename} /tempZone/home/rods/')
            assert_command(f'globus-url-copy gsiftp://{self.hostname}:2811/tempZone/home/rods/{put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/{get_filename}')
            assert_command(f'iget /tempZone/home/rods/{get_filename}')
            assert_command(f'diff -q {put_filename} {get_filename}')

        finally:
            os.remove(put_filename)
            os.remove(get_filename)
            assert_command(f'irm -f /tempZone/home/rods/{put_filename}')
            assert_command(f'irm -f /tempZone/home/rods/{get_filename}')

    def test_file_rename_with_ftp(self):
        filename1 = f'{inspect.currentframe().f_code.co_name}1'
        filename2 = f'{inspect.currentframe().f_code.co_name}2'

        try:
            make_arbitrary_file(filename1, 100*1024)
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                # write the file that will be renamed
                with open(filename1,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename1}', f)

                # verify file exists
                files = ftp.nlst(f'/tempZone/home/user1/{filename1}')
                self.assertEqual(files[0], f'/tempZone/home/user1/{filename1}')

            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                # rename the file
                ftp.rename(f'/tempZone/home/user1/{filename1}', f'/tempZone/home/user1/{filename2}')

                # verify file exists
                files = ftp.nlst(f'/tempZone/home/user1/{filename2}')
                self.assertEqual(files[0], f'/tempZone/home/user1/{filename2}')

                # verify old file does not exist
                with self.assertRaises(error_perm):
                    ftp.nlst(f'/tempZone/home/user1/{filename1}')

                # get the file
                with open(filename2, 'wb') as f:
                    def callback(data):
                        f.write(data)
                    ftp.retrbinary(f'RETR /tempZone/home/user1/{filename2}', callback)


            # verify that the file is unchanged
            assert_command(f'diff -q {filename1} {filename2}')

        finally:
            os.remove(filename1)
            os.remove(filename2)

            # remove file via ftp
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/{filename2}')

    def test_preserve_file_modification_time(self):
        filename = f'{inspect.currentframe().f_code.co_name}1'
        modify_time = '19710827010000'

        try:
            make_arbitrary_file(filename, 100*1024)
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                # tell the server to send a hardcoded file modification time
                ftp.sendcmd(f'site storattr modify={modify_time};')

                # write the file that will be renamed
                with open(filename,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename}', f)

            # check the file modification time
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                rv = ftp.mlsd(f'/tempZone/home/user1/{filename}', facts=['modify'])

                # mlsd returns a generator object yielding a tuple of two elements for every file found in path.
                # First element is the file name, the second one is a dictionary containing facts about the file name. 
                entry = next(rv)
                self.assertEqual(f'/tempZone/home/user1/{filename}', entry[0])
                self.assertEqual(modify_time, entry[1]['modify'])

        finally:
            os.remove(filename)

            # remove file via ftp 
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/{filename}')

    def test_directory_creation_renaming_removal_with_ftp(self):
        filename = f'{inspect.currentframe().f_code.co_name}1'

        try:
            make_arbitrary_file(filename, 100*1024)
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                # make a subdirectory that will be renamed
                ftp.mkd('/tempZone/home/user1/dir1')

                # add a file into the directory for good measure
                with open(filename,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/dir1/{filename}', f)

                # verify file exists
                files = ftp.nlst(f'/tempZone/home/user1/dir1/{filename}')
                self.assertEqual(files[0], f'/tempZone/home/user1/dir1/{filename}')

            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')

                # rename the directory 
                ftp.rename(f'/tempZone/home/user1/dir1', f'/tempZone/home/user1/dir2')

                # verify file exists in new directory
                files = ftp.nlst(f'/tempZone/home/user1/dir2/{filename}')
                self.assertEqual(files[0], f'/tempZone/home/user1/dir2/{filename}')

                # verify old directory does not exist
                with self.assertRaises(error_perm):
                    ftp.nlst(f'/tempZone/home/user1/dir1')

        finally:
            os.remove(filename)

            # remove file and directory via ftp 
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/dir2/{filename}')
                ftp.rmd(f'/tempZone/home/user1/dir2')

    def test_checksums(self):
        filename1 = f'{inspect.currentframe().f_code.co_name}1'
        filename2 = f'{inspect.currentframe().f_code.co_name}2'

        try:
            make_arbitrary_file(filename1, 300*1024*1024)
            make_arbitrary_file(filename2, 1*1024*1024)

            # get various checksum of the files
            checksum_map_filename1 = {}
            checksum_map_filename1['md5'] = hashlib.md5(open(filename1,'rb').read()).hexdigest()
            checksum_map_filename1['sha256'] = hashlib.sha256(open(filename1,'rb').read()).hexdigest()
            checksum_map_filename1['sha512'] = hashlib.sha512(open(filename1,'rb').read()).hexdigest()
            checksum_map_filename1['sha1'] = hashlib.sha1(open(filename1,'rb').read()).hexdigest()
            with open(filename1, "rb") as f:
                data = f.read()
                checksum_map_filename1['adler32'] = hex(zlib.adler32(data))[2:]

            checksum_map_filename2 = {}
            checksum_map_filename2['md5'] = hashlib.md5(open(filename2,'rb').read()).hexdigest()
            checksum_map_filename2['sha256'] = hashlib.sha256(open(filename2,'rb').read()).hexdigest()
            checksum_map_filename2['sha512'] = hashlib.sha512(open(filename2,'rb').read()).hexdigest()
            checksum_map_filename2['sha1'] = hashlib.sha1(open(filename2,'rb').read()).hexdigest()
            with open(filename2, "rb") as f:
                data = f.read()
                checksum_map_filename2['adler32'] = hex(zlib.adler32(data))[2:]

            # debug
            print(checksum_map_filename1)
            print(checksum_map_filename2)

            # Put a file to user1's home directory
            # user1 is defined as the anonymous ftp user
            # At this point I don't know how to put a file to user1 with globus-url-copy.
            # I also don't know how to telnet to a non-anonymous ftp user which I need for checksums.
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                with open(filename1,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename1}', f)

            # get checksum from the file via globus plugin using telnet
            with telnetlib.Telnet('localhost', 2811, 100) as session:
                session.read_until(b'ready.\r\n')
                session.write(b'user user1\r\n')
                session.read_until(b'Password required for user1.\r\n')
                session.write(b'pass\r\n')
                session.read_until(b'User user1 logged in.\r\n')

                for checksum_type, value in checksum_map_filename1.items():
                    # send checksum request via telnet, read response and validate checksums
                    session.write(get_telnet_checksum_command(checksum_type, filename1))
                    checksum = parse_telnet_checksum_response_as_string(session.read_until(b'\r\n'))
                    self.assertEqual(checksum, value, f'{checksum_type} checksums are not equal')

                    # request checksum again and make sure it returns quickly since it is cached in metadata
                    time1 = time.time()
                    session.write(get_telnet_checksum_command(checksum_type, filename1))
                    checksum = parse_telnet_checksum_response_as_string(session.read_until(b'\r\n'))
                    time2 = time.time()
                    self.assertEqual(checksum, value, f'{checksum_type} checksums are not equal')
                    self.assertLess(time2 - time1, 1, f'{checksum_type} checksums took too long to retrieve')

            # overwrite filename1 with filename2
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                with open(filename2,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename1}', f)

            # get and verify checksums.  the cached value in metadata should be discarded and checksums recalculated
            with telnetlib.Telnet('localhost', 2811, 100) as session:
                session.read_until(b'ready.\r\n')
                session.write(b'user user1\r\n')
                session.read_until(b'Password required for user1.\r\n')
                session.write(b'pass\r\n')
                session.read_until(b'User user1 logged in.\r\n')

                for checksum_type, value in checksum_map_filename2.items():
                    # send checksum request via telnet, read response and validate checksums
                    session.write(get_telnet_checksum_command(checksum_type, filename1))
                    checksum = parse_telnet_checksum_response_as_string(session.read_until(b'\r\n'))
                    self.assertEqual(checksum, value, f'{checksum_type} checksums are not equal')

        finally:
            os.remove(filename1)
            os.remove(filename2)

            # remove file via ftp 
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/{filename1}')

    def test_checksum_with_progress_markers(self):
        filename = f'{inspect.currentframe().f_code.co_name}1'

        try:
            # file must be big enough so that checksum takes at least one second
            # otherwise this test will fail after not seeing the marker 
            make_arbitrary_file(filename, 600*1024*1024)

            # get various checksum of the files
            md5 = hashlib.md5(open(filename,'rb').read()).hexdigest()

            # Put a file to user1's home directory
            # user1 is defined as the anonymous ftp user
            # At this point I don't know how to put a file to user1 with globus-url-copy.
            # I also don't know how to telnet to a non-anonymous ftp user which I need for checksums.
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                with open(filename,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename}', f)

            # get checksum from the file via globus plugin using telnet
            # request status markers every second, verify at least one status marker response
            got_status_marker = False
            with telnetlib.Telnet('localhost', 2811, 100) as session:
                session.read_until(b'ready.\r\n')
                session.write(b'user user1\r\n')
                session.read_until(b'Password required for user1.\r\n')
                session.write(b'pass\r\n')
                session.read_until(b'User user1 logged in.\r\n')
                session.write(b'opts cksm markers=1\r\n')
                session.read_until(b'OPTS Command Successful.\r\n')
                session.write(get_telnet_checksum_command('md5', filename))

                # look for markers, keep reading while we get them 
                return_text = session.read_until(b'\r\n')
                return_text_decoded = return_text.decode('utf-8')
                while 'Status Marker' in return_text_decoded:
                    got_status_marker = True
                    session.read_until(b'Timestamp')
                    session.read_until(b'Bytes Processed')
                    session.read_until(b'End.\r\n')
                    return_text = session.read_until(b'\r\n')
                    return_text_decoded = return_text.decode('utf-8')
                self.assertTrue(got_status_marker)
                checksum = parse_telnet_checksum_response_as_string(return_text)
                self.assertEqual(checksum, md5, f'md5 checksums are not equal')

        finally:
            os.remove(filename)

            # remove file via ftp 
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/{filename}')
                
    def test_ips(self):
        # start an ftp session to globus and check ips
        with FTP() as ftp:
            ftp.connect(host='localhost', port=2811)
            ftp.login(user='user1', passwd='pass')
            assert_command('ips', 'STDOUT_SINGLELINE', 'irods_client_globus_connector')

    def test_error_when_gridmapfile_missing(self):
        put_filename = inspect.currentframe().f_code.co_name 

        try:
            make_arbitrary_file(put_filename, 100*1024)

            # remove the mapfile and verify we get an error
            os.rename('/etc/grid-security/grid-mapfile', '/etc/grid-security/grid-mapfile.bu')
            assert_command(f'globus-url-copy {put_filename} gsiftp://{self.hostname}:2811/tempZone/home/rods/', 'STDERR_SINGLELINE', 'Gridmap lookup failure:')

        finally:
            # replace the mapfile
            os.rename('/etc/grid-security/grid-mapfile.bu', '/etc/grid-security/grid-mapfile')

    def test_command_not_implemented(self):
        filename = f'{inspect.currentframe().f_code.co_name}'
        try:
            make_arbitrary_file(filename, 100*1024)
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                with open(filename,'rb') as f:
                    ftp.storbinary(f'STOR /tempZone/home/user1/{filename}', f)
                with self.assertRaises(error_perm):
                    rv = ftp.sendcmd('SITE CHMOD 0755 ' + filename)
                    self.assertIn('iRODS: Command (GLOBUS_GFS_CMD_SITE_CHMOD) is not implemented', rv)
        finally:
            os.remove(filename)
            # remove file via ftp 
            with FTP() as ftp:
                ftp.connect(host='localhost', port=2811)
                ftp.login(user='user1', passwd='pass')
                ftp.delete(f'/tempZone/home/user1/{filename}')

