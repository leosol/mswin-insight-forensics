import os
import json
from datetime import datetime


def parsed_date(dstr):
    ts = None
    try:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S.%f')
    return ts


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


def list_files(directory_path, base_dir=None):
    return _list_files(directory_path=directory_path, base_dir=base_dir, collector=set())


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


def read_json_file_to_dict(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"The file {filename} does not exist.")
    except json.JSONDecodeError:
        print(f"Error decoding JSON from the file {filename}.")
    except Exception as e:
        print(f"An error occurred: {e}")

