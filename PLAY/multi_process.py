import multiprocessing
import os
import time


def worker(file_name):
    if os.path.exists(file_name):
        os.remove(file_name)
    for i in range(5):
        with open(file_name, 'a') as fp:
            fp.write(file_name + '\n')
            print file_name
        time.sleep(1)

    return


if __name__ == '__main__':
    jobs = []
    for i in range(1,3):
        file_name = 'multi_process_{0}.txt'.format(i)
        p = multiprocessing.Process(target=worker, args=(file_name,))
        jobs.append(p)
        p.start()

    for i in jobs:
        p.join()

    print 'END!!!'
