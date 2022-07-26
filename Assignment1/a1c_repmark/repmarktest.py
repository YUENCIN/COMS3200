import sys
import subprocess
import traceback
import time
import os
import socket
import signal
from contextlib import contextmanager

TEST_TIMEOUT = 30

CLIENT_PORT = 0  # auto
MARK_FILE_LOCATION = 'mark_files/'

RUSHB_MARKSUITE_VERSION = '1.0'
'''
1.0 - Initial release
'''


def do_timeout(signum, frame):
    raise TimeoutError


@contextmanager
def timed(time):
    if os.name == "posix":
        signal.signal(signal.SIGALRM, do_timeout)
        signal.alarm(time)
        yield
        signal.signal(signal.SIGALRM, signal.SIG_IGN)  # cancel signal
    else:
        yield


def print_result(id, test_name, result, marks, total_marks, extra=None):
    print(f'Test {id:02}: {result:8} :{test_name:50} :{marks}/{total_marks}', flush=True)
    if extra is not None and len(extra) > 1:
        print('   ' + extra, flush=True)
    return marks


def build(base_folder):
    path = '' if base_folder is None else base_folder
    if os.path.isfile(path + "makefile") or os.path.isfile(path + "Makefile"):
        print('Calling make.')
        try:
            subprocess.check_output(["make"], cwd=base_folder)
        except subprocess.CalledProcessError:
            assert False, "Error occurred while calling make"


class Marker:
    def __init__(self, id, test, marks, base_folder):
        self._id = id
        self._test = test
        self._marks = marks
        self._base_folder = base_folder
        self._path = '' if base_folder is None else base_folder

        self._serv_proc = None
        self._cli_proc = None
        self._cli_proc_2 = None
        self._cli_proc_3 = None
        self._serv_port = None

    def _tear_down(self):
        if self._serv_proc is not None: self._serv_proc.kill()
        if self._cli_proc is not None: self._cli_proc.kill()
        if self._cli_proc_2 is not None: self._cli_proc_2.kill()
        if self._cli_proc_3 is not None: self._cli_proc_3.kill()

    def _assert(self, condition, message):
        if not condition: self._tear_down()
        # stderr_out = self._get_stderr()
        # if stderr_out is not None:
        #     message += "\n\nProcess stderr not empty:\n" + stderr_out
        assert condition, message


    def _start_server(self):
        if os.path.isfile(self._path + "RUSHBSvr.py"):
            self._serv_proc = subprocess.Popen(["python3", "RUSHBSvr.py"], stdout=subprocess.PIPE,
                                               cwd=self._base_folder)
        elif os.path.isfile(self._path + "RUSHBSvr.class"):
            if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                self._serv_proc = subprocess.Popen(["java", "RUSHBSvr"], stdout=subprocess.PIPE, cwd=self._base_folder)
            else:
                self._assert(False, "There is a java class file but no makefile")
        elif os.path.isfile(self._path + "RUSHBSvr"):
            if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                self._serv_proc = subprocess.Popen(["./RUSHBSvr"], stdout=subprocess.PIPE, cwd=self._base_folder)
            else:
                self._assert(False, "There is an executable file but no makefile")
        else:
            self._assert(False, "Could not find assignment file")

    def _get_port(self):
        try:
            out = self._serv_proc.stdout.readline().decode("UTF-8")
            self._serv_port = int(out.partition("\n")[0].strip())
        except subprocess.TimeoutExpired:
            self._assert(False, "No port received from server")
        except ValueError:
            self._assert(False, f"Port {out} not valid")

    def _connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind(("localhost", self._serv_port))
                self._assert(False, "Server is not listening")
            except OSError as e:
                if e.args[0] not in (48, 98):
                    self._assert(False, "Server is not listening")
            except Exception as e2:
                self._assert(False, e2.args[0])


    def _check_output(self, mode=""):
        with open(self._test + mode + "_output.txt", "r") as f, open(
                os.path.join(MARK_FILE_LOCATION, self._test + mode + "_output.txt"), "r") as g:
            output = f.readlines()
            expected = g.readlines()

            if len(output) != len(expected):
                self._assert(False, f'Output length mismatch:\n\t{self._test + mode + "_output.txt"}: {len(output)}\n\t{MARK_FILE_LOCATION + self._test + mode + "_output.txt"}: {len(expected)}')

            for i in range(len(expected)):
                try:
                    if not ((expected[i][0] == output[i][0]) and (expected[i][5:] == output[i][5:])):
                        self._assert(False, f'Expected: {expected[i][5:]} --- Output: {output[i][5:]}')
                except IndexError:
                    self._assert(False, f'Expected: {expected[i][5:]} --- Output: NONE')
        return

    def _run_proc(self, advanced=False):
        self._cli_proc = subprocess.Popen(
            ["python3", "repmarkclient.py", str(CLIENT_PORT), str(self._serv_port), "-m", self._test, "-v", "10",
             "-o", self._test + "_output.txt"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if advanced:
            self._cli_proc_2 = subprocess.Popen(
                ["python3", "repmarkclient.py", str(CLIENT_PORT), str(self._serv_port), "-m", self._test + "_2", "-v", "10",
                 "-o", self._test + "_2_output.txt"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._cli_proc_3 = subprocess.Popen(
                ["python3", "repmarkclient.py", str(CLIENT_PORT), str(self._serv_port), "-m", self._test + "_3", "-v", "10",
                 "-o", self._test + "_3_output.txt"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self._cli_proc.wait(timeout=TEST_TIMEOUT)
        except subprocess.TimeoutExpired:
            self._assert(False, "Timeout exceeded during connection")
            pass
        if advanced:
            try:
                self._cli_proc_2.wait(timeout=TEST_TIMEOUT+7)
            except subprocess.TimeoutExpired:
                pass
            try:
                self._cli_proc_3.wait(timeout=TEST_TIMEOUT+14)
            except subprocess.TimeoutExpired:
                pass


        self._check_output()
        if advanced:
            self._check_output(mode="_2")
            self._check_output(mode="_3")
        return

    def _do_test(self):
        self._start_server()
        if self._test == 'START_SERVER': return

        self._get_port()
        if self._test == 'GET_PORT': return

        if self._test == 'TEST_PORT_CONNECTION':
            self._connect()
            return
        if "ADVANCED" not in self._test:
            self._run_proc()
        else:
            self._run_proc(advanced=True)


    def mark(self):
        try:
            with timed(TEST_TIMEOUT + 1):
                self._do_test()
                self._tear_down()
                return print_result(self._id, self._test, 'PASS', self._marks, total_marks=self._marks, extra=None)
        except TimeoutError:
            return print_result(self._id, self._test, 'TIMEOUT', 0, total_marks=self._marks,
                                extra=f"Timeout of {str(TEST_TIMEOUT + 1)} seconds exceeded")
        except AssertionError as e:
            return print_result(self._id, self._test, 'FAIL', 0, total_marks=self._marks, extra=e.args[0])
        except:
            return print_result(self._id, self._test, 'ERROR', 0, total_marks=self._marks, extra=traceback.format_exc())


def main(argv):
    path = os.getcwd()
    print('RUSHB_MARKSUITE_VERSION:' + RUSHB_MARKSUITE_VERSION + " [" + path[-5:] + "]")
    print('--------------------------------------------------------------------------')
    if len(argv) > 2:
        print("Usage: python3 repmarktest.py [path_to_RUSHBSvr/]")
        return

    test_folder = argv[1] if len(argv) == 2 else None

    # feedback = open("feedback.txt", "w")
    # save_stdout = sys.stdout
    # sys.stdout = feedback

    try:
        build(test_folder)
    except AssertionError as e:
        print("Make file Error:" + e.args[0])

    marks = -1

    tests_marks = {
                   "SIMPLE": 1, 
                   "SIMPLE2": 1,
                   "BAD1_SIMPLE": 1,
                   "BAD2_SIMPLE": 1,
                   "BAD1_SIMPLE2": 1,
                   "BAD2_SIMPLE2": 1,
                   "BAD_INVALID_ACK": 1,
                   "INVALID_ACK": 1,
                   "INVALID_FLAGS": 1,
                   "CHECKSUM": 1,
                   "INVALID_CHECKSUM_VAL": 1,
                   "INVALID_CHECKSUM_FLAG": 1,
                   "BAD_CHECKSUM": 1,
                   "STABLE": 1,
                   "NAK": 2,
                   "MULTI_NAK": 3,
                   "TIMEOUT": 2,
                   "MULTI_TIMEOUT": 3,
                   "STABLE_INIT_MUL_CLIENTS": 1,
                   "ADVANCED_MUL_CLIENTS_SIMPLE": 5,
                   "ADVANCED_MUL_CLIENTS_MIX": 6
                   }

    marks = Marker(1, 'START_SERVER', 1, base_folder=test_folder).mark()
    if marks == 1: marks += Marker(2, 'GET_PORT', 2, base_folder=test_folder).mark()
    if marks == 3: marks += Marker(3, 'TEST_PORT_CONNECTION', 2, base_folder=test_folder).mark()
    i = 3
    if marks == 5:
        for test, mark in tests_marks.items():
            i += 1
            marks += Marker(i, test, mark, base_folder=test_folder).mark()
            # if i == 24: break
    # marks = int(marks)  # <<<<<<<<<<<<<<<<<
    print('--------------------------------------------------------------------------')
    print(f"Total marks: {marks}/41")

    return marks

    # sys.stdout = save_stdout
    # feedback.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
