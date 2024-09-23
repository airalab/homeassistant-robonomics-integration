import typing as tp

def is_ipfs_path_dir(file_info: tp.Optional[str]) -> bool:
    if file_info is None:
        return False
    else:
        return file_info["Type"] == "directory"


def format_files_list(files_list: tp.Optional[dict]) -> tp.List[str]:
    item_names = [item["Name"] for item in files_list]
    return item_names
