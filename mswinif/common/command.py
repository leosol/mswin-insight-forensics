import logging
import subprocess
import threading


class Command:
    def __init__(self, cmd=[]):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cmd = cmd
        self.process = None
        self.stdout = None
        self.stderr = None

    def run(self, timeout=60 * 20):
        def target():
            self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = self.process.communicate()
            try:
                self.stdout = stdout.decode('utf-8')
            except:
                self.stdout = str(stdout)
            try:
                self.stderr = stderr.decode('utf-8')
            except:
                self.stderr = str(stderr)

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.logger.warning(f"Timeout reached ({timeout}s). Forcing process {str(self.cmd)} to terminate")
            self.process.terminate()
            thread.join()
        else:
            self.logger.debug(f"Process {str(self.cmd)} finished with return code {self.process.returncode}")
