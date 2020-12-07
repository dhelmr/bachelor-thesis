import unittest

import numpy

from canids.feature_extractors.payl import ByteDistributionInfo


class PaylTest(unittest.TestCase):
    def test_byte_distributions(self):
        byte_counts = [40] * 128 + [0] * 128
        freq = [x / (40 * 128) for x in byte_counts]
        distr1 = ByteDistributionInfo.init_with(
            byte_counts=byte_counts, packet_length=40 * 128
        )
        self.arraysEqual(distr1.mean_byte_freq, freq)
        self.arraysEqual(distr1.mean_squared_freq, [pow(x, 2) for x in freq])
        self.assertEqual(distr1.packet_length, 40 * 128)
        self.arraysEqual(distr1.stddevs, [0] * 256)

        freq = [0.25, 0.1, 0.1, 0.5, 0.05]
        byte_counts = [x * 4000 for x in freq]
        distr1 = ByteDistributionInfo.init_with(
            byte_counts=byte_counts, packet_length=4000
        )
        for i in range(100):
            distr1 = distr1.update_with(new_byte_counts=byte_counts)
        self.arraysEqual(distr1.mean_byte_freq, freq)
        self.arraysEqual(distr1.mean_squared_freq, [pow(x, 2) for x in freq])
        self.assertEqual(distr1.packet_length, 4000)
        self.arraysEqual(distr1.stddevs, [0] * 5)

    def arraysEqual(self, exp: numpy.ndarray, act, **kwargs):
        if type(act) is list:
            act = numpy.array(act)
        return self.assertTrue(
            numpy.equal(exp, act).all(), msg="Not equal: %s %s" % (exp, act)
        )


if __name__ == "__main__":
    unittest.main()
