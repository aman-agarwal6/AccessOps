import unittest

from publish_recordings import check_detail


class CheckDetailTests(unittest.TestCase):
    def test_measured_duration_is_published(self):
        self.assertEqual(
            check_detail("the lab", {"duration_seconds": 5.843908}),
            "Actual check using the lab. Took 5.84 s.",
        )

    def test_bookkeeping_and_missing_durations_are_left_out(self):
        for item in ({"duration_seconds": 0.002}, {}, {"duration_seconds": float("nan")}):
            self.assertEqual(check_detail("the lab", item), "Actual check using the lab.")

    def test_only_numbers_count_as_durations(self):
        self.assertEqual(
            check_detail("the lab", {"duration_seconds": "5"}), "Actual check using the lab."
        )


if __name__ == "__main__":
    unittest.main()
