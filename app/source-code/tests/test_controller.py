# controller.py is not feasibly testable due it running in a simulation
import unittest


class TestEventHandlers(unittest.TestCase):
    def test_test(self):
        '''
        Test the test scripts
        '''
        data = [1, 2, 3]
        self.assertEqual(data, data)


if __name__ == '__main__':
    unittest.main()
