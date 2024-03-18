import requests
import hashlib
import sys

# try to read the inputed password from a text file
# needs to be improve with gui

# function to request data from api
def request_api_data(query_char):
    # API
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    # check
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check api and try again')
    return res

# funcion to check number of leak passwords
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# function to check if password is pwned
def pwned_api_check(password):
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found in the pwned password list. Carry on!')
    return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))