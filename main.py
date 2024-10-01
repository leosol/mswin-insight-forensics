import argparse
import logging
import os.path
import signal
import sys
from mswinif.Project import Project
from mswinif.utils import destroy_dir_files, list_files


def signal_handler(signal, frame):
    print('You pressed Ctrl+C! Exiting gracefully.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def parse_args():
    parser = argparse.ArgumentParser(description="Start MSWin-Insight Forensics",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("--debug", action="store_true", dest="debug_mode",
                        help="Run in debug mode (dump debug messages).")
    parser.add_argument("--force", action="store_true", dest="force",
                        help="Remove output dir if it exists")
    parser.add_argument("-i", action="store", dest="input_dir", required=False,
                        default="input",
                        help="The input dir with extracted files")
    parser.add_argument("-input", action="store", dest="input_dir", required=False,
                        default="input",
                        help="The input dir with extracted files")
    parser.add_argument("-o", action="store", dest="output_dir", required=False,
                        default=".\\output",
                        help="The output dir which will have the data")
    parser.add_argument("-output", action="store", dest="output_dir", required=False,
                        default=".\\output",
                        help="The output dir which will have the data")
    parser.add_argument("-tmp_dir", action="store", dest="tmp_dir", required=False,
                        default=".\\tmp",
                        help="The temp dir which will have temp data")
    parser.add_argument("-tools_dir", action="store", dest="tools_dir", required=False,
                        default=".\\tools",
                        help="The tools dir")
    options = parser.parse_args()
    return options


def main():
    opts = parse_args()
    input_dir = opts.input_dir
    output_dir = opts.output_dir
    tools_dir = opts.tools_dir
    tmp_dir = opts.tmp_dir
    force = opts.force
    if os.path.exists(output_dir):
        if force:
            destroy_dir_files(output_dir)
            os.makedirs(output_dir)
        else:
            files = list_files(output_dir)
            if len(files) > 0:
                raise RuntimeError('Output dir is not empty. Use force to overwrite.')
    else:
        os.makedirs(output_dir)
    logging.basicConfig(level=logging.DEBUG if opts.debug_mode else logging.INFO)
    project = Project(input_dir=input_dir, output_dir=output_dir, tools_dir=tools_dir, tmp_dir=tmp_dir)
    project.process()


if __name__ == "__main__":
    main()
