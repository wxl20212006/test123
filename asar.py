# -*- coding: UTF-8 -*-
import io
import os
import json
import struct
import shutil
import argparse
import sys
from os.path import join, islink
from os import listdir, lstat, stat, strerror

# 完整性检查
import hashlib

ALGORITHM = 'SHA256'
# 4MB default block size
BLOCK_SIZE = 4 * 1024 * 1024

# 计算字符串 SHA256 的 HASH 值
def str_sha256(s):
    hasher = hashlib.sha256()
    hasher.update(s.encode('utf-8'))
    return hasher.hexdigest()

def hash_block(block):
    return hashlib.sha256(block).hexdigest()


blocks = []
current_block_size = 0
current_block = []


def get_file_integrity(path):
    global blocks, current_block_size, current_block

    def internal_get_integrity(path):
        file_hash = hashlib.sha256()
        global blocks, current_block_size, current_block

        with open(path, 'rb') as f:
            while True:
                buf = f.read(BLOCK_SIZE)
                if not buf:
                    break
                file_hash.update(buf)

                def handle_chunk(chunk):
                    global current_block_size, current_block

                    diff_to_slice = min(BLOCK_SIZE - current_block_size, len(chunk))
                    current_block_size += diff_to_slice
                    current_block.append(chunk[:diff_to_slice])
                    if current_block_size == BLOCK_SIZE:
                        blocks.append(hash_block(b''.join(current_block)))
                        current_block = []
                        current_block_size = 0
                    if diff_to_slice < len(chunk):
                        handle_chunk(chunk[diff_to_slice:])

                handle_chunk(buf)

        if current_block_size > 0:
            blocks.append(hash_block(b''.join(current_block)))

        return {
            'algorithm': ALGORITHM,
            'hash': file_hash.hexdigest(),
            'blockSize': BLOCK_SIZE,
            'blocks': blocks
        }

    blocks = []
    current_block_size = 0
    current_block = []
    return internal_get_integrity(path)





# 兼容python2
class GenericDirEntry(object):
    __slots__ = ('name', '_stat', '_lstat', '_scandir_path', '_path')

    def __init__(self, scandir_path, name):
        self._scandir_path = scandir_path
        self.name = name
        self._stat = None
        self._lstat = None
        self._path = None

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._scandir_path, self.name)
        return self._path

    def stat(self, follow_symlinks=True):
        if follow_symlinks:
            if self._stat is None:
                self._stat = stat(self.path)
            return self._stat
        else:
            if self._lstat is None:
                self._lstat = lstat(self.path)
            return self._lstat

    # The code duplication below is intentional: this is for slightly
    # better performance on systems that fall back to GenericDirEntry.
    # It avoids an additional attribute lookup and method call, which
    # are relatively slow on CPython.
    def is_dir(self, follow_symlinks=True):
        try:
            st = self.stat(follow_symlinks=follow_symlinks)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFDIR

    def is_file(self, follow_symlinks=True):
        try:
            st = self.stat(follow_symlinks=follow_symlinks)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFREG

    def is_symlink(self):
        try:
            st = self.stat(follow_symlinks=False)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFLNK

    def inode(self):
        st = self.stat(follow_symlinks=False)
        return st.st_ino

    def __str__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.name)

    __repr__ = __str__
scandir=None
if sys.version_info[0] < 3:
    def scandir(path=unicode('.')):
        """Like os.listdir(), but yield DirEntry objects instead of returning
        a list of names.
        """
        for name in listdir(path):
            yield GenericDirEntry(path, name)
else:
    scandir=os.scandir
# 兼容python2 结束
def round_up(i, m):
    """Rounds up ``i`` to the next multiple of ``m``.

    ``m`` is assumed to be a power of two.
    """
    return (i + m - 1) & ~(m - 1)


class Asar:

    """Represents an asar file.

    You probably want to use the :meth:`.open` or :meth:`.from_path`
    class methods instead of creating an instance of this class.

    Attributes
    ----------
    path : str
        Path of this asar file on disk.
        If :meth:`.from_path` is used, this is just
        the path given to it.
    fp : File-like object
        Contains the data for this asar file.
    header : dict
        Dictionary used for random file access.
    base_offset : int
        Indicates where the asar file header ends.
    """

    def __init__(self, path, fp, header, base_offset, hash=None):
        self.path = path
        self.fp = fp
        self.header = header
        self.base_offset = base_offset
        self.hash = hash

    @classmethod
    def open(cls, path):
        """Decodes the asar file from the given ``path``.

        You should use the context manager interface here,
        to automatically close the file object when you're done with it, i.e.

        .. code-block:: python

            with Asar.open('./something.asar') as a:
                a.extract('./something_dir')

        Parameters
        ----------
        path : str
            Path of the file to be decoded.
        """
        fp = open(path, 'rb')

        # decode header
        # NOTE: we only really care about the last value here.
        data_size, header_size, header_object_size, header_string_size = struct.unpack(
            '<4I', fp.read(16))

        header_json = fp.read(header_string_size).decode('utf-8')

        return cls(
            path=path,
            fp=fp,
            header=json.loads(header_json),
            base_offset=round_up(16 + header_string_size, 4)
        )

    @classmethod
    def from_path(cls, path):
        """Creates an asar file using the given ``path``.

        When this is used, the ``fp`` attribute of the returned instance
        will be a :class:`io.BytesIO` object, so it's not written to a file.
        You have to do something like:

        .. code-block:: python

            with Asar.from_path('./something_dir') as a:
                with open('./something.asar', 'wb') as f:
                    a.fp.seek(0) # just making sure we're at the start of the file
                    f.write(a.fp.read())

        You cannot exclude files/folders from being packed yet.

        Parameters
        ----------
        path : str
            Path to walk into, recursively, and pack
            into an asar file.
        """
        _nonlocal = {
            "offset": 0,
            "concatenated_files": b'',
        }
        def _path_to_dict(path):
            # concatenated_files, offset
            result = {'files': {}}

            for f in scandir(path):
                if os.path.islink(f.path):
                    size = f.stat().st_size
                    result['files'][f.name] = {
                        'size': size,
                        'unpacked': True
                    }
                elif os.path.isdir(f.path):
                    result['files'][f.name] = _path_to_dict(f.path)
                else:
                    size = f.stat().st_size

                    result['files'][f.name] = {
                        'size': size,
                        'offset': str(_nonlocal["offset"]),
                        "integrity": get_file_integrity(f.path)
                    }

                    with open(f.path, 'rb') as fp:
                        _nonlocal["concatenated_files"] += fp.read()

                    _nonlocal["offset"] += size

            return result

        header = _path_to_dict(path)
        header_json = json.dumps(
            header, sort_keys=True, separators=(',', ':')).encode('utf-8')

        header_hash = str_sha256(header_json)

        # TODO: using known constants here for now (laziness)...
        #       we likely need to calc these, but as far as discord goes we haven't needed it.
        header_string_size = len(header_json)
        data_size = 4  # uint32 size
        aligned_size = round_up(header_string_size, data_size)
        header_size = aligned_size + 8
        header_object_size = aligned_size + data_size

        # pad remaining space with NULLs
        diff = aligned_size - header_string_size
        header_json = header_json + b'\0' * (diff) if diff else header_json

        fp = io.BytesIO()
        fp.write(struct.pack('<4I', data_size, header_size,
                             header_object_size, header_string_size))
        fp.write(header_json)
        fp.write(_nonlocal["concatenated_files"])

        return cls(
            path=path,
            fp=fp,
            header=header,
            base_offset=round_up(16 + header_string_size, 4),
            hash=header_hash
        )

    def _copy_unpacked_file(self, source, destination):
        """Copies an unpacked file to where the asar is extracted to.

        An example:

            .
            ├── test.asar
            └── test.asar.unpacked
                ├── abcd.png
                ├── efgh.jpg
                └── test_subdir
                    └── xyz.wav

        If we are extracting ``test.asar`` to a folder called ``test_extracted``,
        not only the files concatenated in the asar will go there, but also
        the ones inside the ``*.unpacked`` folder too.

        That is, after extraction, the previous example will look like this:

            .
            ├── test.asar
            ├── test.asar.unpacked
            |   └── ...
            └── test_extracted
                ├── whatever_was_inside_the_asar.js
                ├── junk.js
                ├── abcd.png
                ├── efgh.jpg
                └── test_subdir
                    └── xyz.wav

        In the asar header, they will show up without an offset, and ``"unpacked": true``.

        Currently, if the expected directory doesn't already exist (or the file isn't there),
        a message is printed to stdout. It could be logged in a smarter way but that's a TODO.

        Parameters
        ----------
        source : str
            Path of the file to locate and copy
        destination : str
            Destination folder to copy file into
        """
        unpacked_dir = self.path + '.unpacked'
        if not os.path.isdir(unpacked_dir):
            print("Couldn't copy file {}, no extracted directory".format(source))
            return

        src = os.path.join(unpacked_dir, source)
        if not os.path.exists(src):
            print("Couldn't copy file {}, doesn't exist".format(src))
            return

        dest = os.path.join(destination, source)
        shutil.copyfile(src, dest)
    def _link_unpack_file(self, source, destination):
        unpacked_dir = self.path + '.unpacked'
        if not os.path.isdir(unpacked_dir):
            print("Couldn't copy file {}, no extracted directory".format(source))
            return

        src = os.path.join(unpacked_dir, source)
        if not os.path.exists(src):
            print("Couldn't copy file {}, doesn't exist".format(src))
            return

        dest = os.path.join(destination, source)
        os.symlink(src, dest)
    def _extract_file(self, source, info, destination):
        """Locates and writes to disk a given file in the asar archive.

        Parameters
        ----------
        source : str
            Path of the file to write to disk
        info : dict
            Contains offset and size if applicable.
            If offset is not given, the file is assumed to be
            sitting outside of the asar, unpacked.
        destination : str
            Destination folder to write file into

        See Also
        --------
        :meth:`._copy_unpacked_file`
        """
        if 'offset' not in info:
            # 使用copy 注入完成后会将零时目录清理，导致symlink失效
            self._copy_unpacked_file(source, destination)
            # self._link_unpack_file(source, destination)
            return

        self.fp.seek(self.base_offset + int(info['offset']))
        r = self.fp.read(int(info['size']))

        dest = os.path.join(destination, source)
        with open(dest, 'wb') as f:
            f.write(r)

    def _extract_directory(self, source, files, destination):
        """Extracts all the files in a given directory.

        If a sub-directory is found, this calls itself as necessary.

        Parameters
        ----------
        source : str
            Path of the directory
        files : dict
            Maps a file/folder name to another dictionary,
            containing either file information,
            or more files.
        destination : str
            Where the files in this folder should go to
        """
        dest = os.path.normcase(os.path.join(destination, source))

        if not os.path.exists(dest):
            os.makedirs(dest)

        for name, info in files.items():
            item_path = os.path.join(source, name)
            if 'files' in info:
                self._extract_directory(item_path, info['files'], destination)
                continue

            self._extract_file(item_path, info, destination)

    def extract(self, path):
        """Extracts this asar file to ``path``.

        Parameters
        ----------
        path : str
            Destination of extracted asar file.
        """
        if os.path.exists(path):
            raise FileExistsError()

        self._extract_directory('.', self.header['files'], path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fp.close()



class Unpack(object):

    def __init__(self, file):
        self.file = file
        self.error_code = 0
        with open(self.file, "rb") as f:
            f.seek(8)
            self.baseOffset = struct.unpack("I", f.read(4))[0] + 12
            header_length = struct.unpack("I", f.read(4))[0]
            try:
                self.header = json.loads(f.read(header_length).decode())
            except:
                self.error_code = -1

    def _extractFile(self, relativeOffset, size, output):
        with open(self.file, "rb") as i:
            i.seek(self.baseOffset + relativeOffset)
            with open(output, "wb") as o:
                o.write(i.read(size))

    def listFiles(self):
        def list_sub_files(folder, path=""):
            files = []
            for k, v in folder.items():
                if k == "files" or "files" in v:
                    for item in list_sub_files(v, path if k == "files" else os.path.join(path, k)):
                        files.append(item)

                if ("unpacked" in v and v["unpacked"]) or k == "files":
                    continue

                files.append({
                    "path": os.path.join(path, k),
                    "size": int(v["size"]) if "size" in v else None,
                    "offset": int(v["offset"]) if "offset" in v else None,
                    "is_file": "size" in v and "offset" in v
                })
            return files

        return list_sub_files(self.header["files"])

    def extractFile(self, inFile, outFile):
        for f in self.listFiles():
            if (os.path.normpath(inFile) == os.path.normpath(f["path"])) and f["is_file"]:
                self._extractFile(f["offset"], f["size"], outFile)
                break

    def _mkdirs(self, dir):
        if not os.path.exists(dir):
            os.makedirs(dir)

    def extractFiles(self, outDir):
        if self.error_code != 0: # 头文件读取失败
            shutil.rmtree(outDir)
            return

        file_size = os.path.getsize(self.file)
        self._mkdirs(outDir)
        for f in self.listFiles():
            fullPath = os.path.join(outDir, f["path"])
            if not f["is_file"]:
                self._mkdirs(fullPath)
                continue

            self._mkdirs(os.path.dirname(fullPath))
            if self.baseOffset + f["offset"] + f["size"] > file_size:
                self.error_code = -1
                break
            self._extractFile(f["offset"], f["size"], fullPath)

        if self.error_code != 0: # 文件大小不匹配
            shutil.rmtree(outDir)


class Pack(object):

    def __init__(self, inFolder, outFile, hashPath):
        self.inFolder = inFolder
        self.outFile = outFile
        self.hashPath = hashPath
        self.tempFile = self.outFile + ".tmp"

    def pack(self):
        def list_sub_files(folder):
            files = {
                "files": {}
            }
            for f in os.listdir(folder):
                fullPath = os.path.join(folder, f)
                if os.path.isdir(fullPath):
                    files["files"][f] = list_sub_files(fullPath)
                    continue

                if os.path.islink(fullPath):
                    size = os.stat(fullPath).st_size
                    files['files'][f] = {
                        'size': size,
                        'unpacked': True
                    }
                    continue

                with open(fullPath, "rb") as i:
                    with open(self.tempFile, "ab") as o:
                        offset = o.tell()
                        o.write(i.read())

                files["files"][f] = {
                    "size": os.stat(fullPath).st_size,
                    "offset": str(offset),
                    "integrity": get_file_integrity(fullPath)
                }
            return files

        header = json.dumps(list_sub_files(self.inFolder), separators=(",", ":")).encode("utf-8")
        header_hash = str_sha256(header)

        with open(self.hashPath, "wb") as f:
            f.write(header_hash)

        with open(self.outFile, "wb") as f:
            f.write(struct.pack("I", 4))
            f.write(struct.pack("I", len(header) + 8))
            f.write(struct.pack("I", len(header) + 4))
            f.write(struct.pack("I", len(header)))
            f.write(header)
            with open(self.tempFile, "rb") as i:
                chunkSize = 2 ** 14
                for data in iter(lambda: i.read(chunkSize), b""):
                    f.write(data)

        os.remove(self.tempFile)



if __name__ == '__main__':
    import sys
    if sys.getdefaultencoding() != 'utf-8':
        reload(sys)
        sys.setdefaultencoding('utf-8')

    parser = argparse.ArgumentParser(description='unpack/pack asar')
    parser.add_argument('action', metavar='action', choices=[
                        "pack", "unpack"], help='pack/unpack asar')
    parser.add_argument('input', metavar='input', help='input path')
    parser.add_argument('output', metavar='output', help='output path')
    parser.add_argument('hash', metavar='hash', help='hash path')
    parser.add_argument("-f", "--force", help="force", action="store_true")
    args = parser.parse_args()
    # print(args)
    if os.path.exists(args.output):
        if args.force:
            if os.path.isdir(args.output):
                shutil.rmtree(args.output)
            else:
                os.remove(args.output)
        else:
            print(args.output + " already exist")
            exit(1)
    if args.action == "pack":
        # with Asar.from_path(args.input) as a:
        #     with open(args.output, 'wb') as f:
        #         a.fp.seek(0)
        #         f.write(a.fp.read())
        #
        #     with open(args.hash, 'wb') as f:
        #         if a.hash is not None:
        #             f.write(a.hash)

        Pack(args.input, args.output, args.hash).pack()
    else:
        with Asar.open(args.input) as a:
            a.extract(args.output)
        # Unpack(args.input).extractFiles(args.output)
