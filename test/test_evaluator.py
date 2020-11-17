import unittest

from canids.evaluator import Evaluator


class EvaluatorTest(unittest.TestCase):
    def testcase_1(self):
        tp, fp, fn, tn = (123, 987, 1343, 2412)
        metrics = Evaluator.calc_measurements(tn, fp, fn, tp)
        self.assert_rounded(metrics["accuracy"], 0.5211)
        self.assert_rounded(metrics["positives"], 1466)
        self.assert_rounded(metrics["negatives"], 3399)
        self.assert_rounded(metrics["precision"], 0.1108)
        self.assert_rounded(metrics["recall"], 0.0839)
        self.assert_rounded(metrics["tnr"], 0.7096)
        self.assert_rounded(metrics["npv"], 0.6423)
        self.assert_rounded(metrics["fpr"], 0.2904)
        self.assert_rounded(metrics["fdr"], 0.8892)
        self.assert_rounded(metrics["fnr"], 0.9161)
        self.assert_rounded(metrics["f1_score"], 0.0955)
        self.assertEqual(metrics["false_positives"], fp)
        self.assertEqual(metrics["false_negatives"], fn)
        self.assertEqual(metrics["true_positives"], tp)
        self.assertEqual(metrics["true_positives"], tp)
        self.assertEqual(metrics["support"], 4865)
        self.assert_rounded(metrics["kappa"], -0.2218)
        self.assert_rounded(metrics["mcc"], -0.2258)
        # left: for, support, balanced accuracy

    def assert_rounded(self, value, expected):
        self.assertEqual(round(value, 4), expected)


if __name__ == "__main__":
    unittest.main()
