import traceback
from framework.exceptions.nutest_error import NuTestError
from framework.lib.nulog import INFO as INFO1, STEP, ERROR
from workflows.monitor_util.monitor_lib import MonitorUtil
import time
import multiprocessing
import signal

marker = '#' * 10 + ' '


def INFO(str):
    INFO1(marker + str)


def main_method():
    INFO('main_method BEGIN')
    time.sleep(10)
    INFO('main_method END')
    # raise NuTestError('main fails')


def side_method_01():
    def sigterm_handler(signum, frame):
        INFO("Sigterm handler called with signal: %s in method:"
             "'side_method_01' " % (signum))

    signal.signal(signal.SIGTERM, sigterm_handler)
    INFO('side_method_01 BEGIN')
    p = multiprocessing.Process(target=child_01)
    p.start()
    p.join()
    INFO('side_method_01 END')
    # Need to let parent know child failing
    if p.exitcode:
        raise NuTestError('side_method_01 failed due to his child failing')


def child_01():
    INFO('child_01 BEGIN')
    time.sleep(5)
    INFO('child_01 END')
    raise NuTestError('child_01 fails')


if __name__ == '__main__':
    parallel_test_methods = {}
    parallel_test_methods["run_side_methods_01"] = [
        side_method_01,"FAIL_TEST_ON_FAILURE", "RESTART_ON_SUCCESS"]

    monitor = MonitorUtil("test_play_for_monitor", main_method,
                          parallel_test_methods, 2)
    monitor.start_main_method()
    # time.sleep(12)
    monitor.start_other_methods()
    INFO('MonitorUtil returned => ' + str(monitor.start_monitoring()))
