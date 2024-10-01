import os
import shutil
from datetime import datetime
from mswinif import utils


def get_immediate_parent_folder(full_path):
    return os.path.dirname(full_path)


def get_file_without_parent(full_path):
    return os.path.basename(full_path)


def get_file_name_without_extension(path, is_full_path=True):
    if is_full_path:
        file_name = get_file_without_parent(path)
    else:
        file_name = path
    return os.path.splitext(file_name)[0]


def get_file_extension(path, is_full_path=True):
    if is_full_path:
        file_name = get_file_without_parent(path)
    else:
        file_name = path
    return os.path.splitext(file_name)[1]


def move_file(source, destination):
    try:
        if not os.path.isfile(source):
            return False
        destination_dir = os.path.dirname(destination)
        if not os.path.exists(destination_dir):
            os.makedirs(destination_dir)
        shutil.move(source, destination)
        return True
    except Exception as e:
        return False


def copy_file(source, destination, force=True):
    try:
        if not os.path.isfile(source):
            return False
        if os.path.exists(destination) and os.path.isfile(destination):
            if force:
                os.remove(destination)
            else:
                raise RuntimeError("Destination exists. Use force to overwrite")
        if os.path.isdir(destination):
            immediate_dir = destination
        else:
            immediate_dir = os.path.dirname(destination)
        if not os.path.exists(immediate_dir):
            os.makedirs(immediate_dir)
        shutil.copy(source, destination)
        return True
    except Exception as e:
        return False


def destroy_dir_files(directory_path, base_dir=None):
    if base_dir is not None:
        file_path = os.path.join(base_dir, directory_path)
    else:
        file_path = directory_path
    for root, dirs, files in os.walk(file_path):
        for file in files:
            file_path_item = os.path.join(root, file)
            try:
                os.remove(file_path_item)
            except Exception as e:
                print(f"Error removing {file_path_item}: {e}")
        for dir_item in dirs:
            dir_path_item = os.path.join(root, dir_item)
            try:
                destroy_dir_files(dir_path_item)
            except Exception as e:
                print(f"Error removing {dir_path_item}: {e}")
    try:
        if os.path.exists(file_path):
            os.removedirs(file_path)
    except Exception as e:
        print(f"Error removing {file_path}: {e}")


def list_files(directory_path, base_dir=None, extension=None):
    file_list = _list_files(directory_path=directory_path, base_dir=base_dir, collector=set())
    if extension is not None:
        if not extension.startswith('.'):
            extension = f".{extension}"
        file_list = [item for item in file_list if get_file_extension(item) == extension]
    return file_list

def _list_files(directory_path, base_dir=None, collector=set()):
    if base_dir is not None:
        file_path = os.path.join(base_dir, directory_path)
    else:
        file_path = directory_path
    for root, dirs, files in os.walk(file_path):
        for file in files:
            file_path_item = os.path.join(root, file)
            collector.add(file_path_item)
        for dir_item in dirs:
            dir_path_item = os.path.join(root, dir_item)
            _list_files(dir_path_item, collector=collector)
    return collector


def get_tmp_file(tmp_dir, tag="", extension=None):
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if extension is not None:
        extension = f".{extension}"
    else:
        extension = ""
    temp_file_path = os.path.join(tmp_dir,
                                  f"tmp-file-{tag}-{current_time}-{utils.generate_random_string()}{extension}")
    return temp_file_path


def get_tmp_dir(tmp_dir, tag=""):
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    temp_file_path = os.path.join(tmp_dir,
                                  f"tmp-dir-{tag}-{current_time}-{utils.generate_random_string()}")
    return temp_file_path


def read_file_lines(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        return [line.strip() for line in lines]  # Removing any leading/trailing whitespace
    except FileNotFoundError:
        print(f"The file {file_path} was not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
