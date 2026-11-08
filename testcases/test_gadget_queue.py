import multiprocessing
import os
import threading
import unittest

from ropper.rop import create_gadget_queue


def _fail_start(self):
    raise RuntimeError("can't start new thread")


def _put_without_threads(queue):
    # Simulate a child process that has exhausted its thread limit, as
    # happens under pwndbg. multiprocessing.Queue would try to start its
    # feeder thread here and raise RuntimeError.
    threading.Thread.start = _fail_start
    queue.put('payload')


def _run_forked_search(result_queue):
    from ropper.loaders.loader import Loader
    from ropper.rop import Ropper

    original = Ropper._Ropper__gatherGadgetsByEndings

    def gather_without_threads(ropper, *args, **kwargs):
        threading.Thread.start = _fail_start
        return original(ropper, *args, **kwargs)

    Ropper._Ropper__gatherGadgetsByEndings = gather_without_threads
    try:
        binary = Loader.open('test-binaries/ls-x86_64')
        ropper = Ropper()
        gadgets = ropper._searchGadgetsForked(binary.executableSections[0], binary)
        result_queue.put(('ok', len(gadgets)))
    except BaseException as exc:
        result_queue.put(('error', repr(exc)))


class GadgetQueueTest(unittest.TestCase):
    def test_put_works_in_a_process_that_cannot_start_threads(self):
        queue = create_gadget_queue()
        process = multiprocessing.Process(target=_put_without_threads, args=(queue,))
        process.start()
        process.join(30)
        try:
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(queue.get(), 'payload')
        finally:
            if process.is_alive():
                process.terminate()
                process.join()


@unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
class ForkedGadgetSearchTest(unittest.TestCase):
    def test_search_works_when_children_cannot_start_threads(self):
        ctx = multiprocessing.get_context('fork')
        result_queue = ctx.Queue()
        process = ctx.Process(target=_run_forked_search, args=(result_queue,))
        process.start()
        process.join(120)
        if process.is_alive():
            process.terminate()
            process.join()
            self.fail('forked gadget search did not finish')
        self.assertEqual(process.exitcode, 0)
        status, value = result_queue.get(timeout=10)
        self.assertEqual(status, 'ok', value)
        self.assertGreater(value, 0)


if __name__ == '__main__':
    unittest.main()
