from io import BytesIO
import tarfile

def extract_archive(self, tar_content: bytes, dir_with_path: str):
    tar_buffer = BytesIO()
    tar_buffer.write(tar_content)
    tar_buffer.seek(0)
    with tarfile.open(fileobj=tar_buffer, mode="r:*") as tar:
        subdir_and_files = []
        for tarinfo in tar.getmembers():
            if tarinfo.name.startswith(f"{self.ipfs_hash}/"):
                tarinfo.path = tarinfo.path.replace(f"{self.ipfs_hash}/", "")
                subdir_and_files.append(tarinfo)
        tar_buffer.seek(0)
        tar.extractall(members=subdir_and_files, path=dir_with_path)
