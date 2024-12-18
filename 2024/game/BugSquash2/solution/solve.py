import requests
import itertools
import time

BASE_URL = 'http://127.0.0.1'


def generate_variations(s):
    """Generate all case variations of a string."""
    return [''.join(variant) for variant in itertools.product(*([letter.lower(), letter.upper()] for letter in s))]


def start_game(session):
    """Start a new game session and return the user_id."""
    response = session.post('{BASE_URL}/start_game')
    response_data = response.json()
    user_id = response_data['user_id']
    score = response_data['score']
    print(f"Game started! User ID: {user_id}, Initial Score: {score}")
    return user_id, score


def update_score(session, user_id, variations):
    """Send score updates to the server using all variations of 'bugs_squashed'."""
    json_data = {"user_id": user_id}
    json_data.update({variation: 1 for variation in variations})

    response = session.post(
        '{BASE_URL}/update_score', json=json_data)
    response_data = response.json()

    if "error" in response_data:
        print(f"Error: {response_data['error']}")
    elif "message" in response_data:
        print(
            f"Message: {response_data['message']}, Current Score: {response_data['score']}")

    return response_data.get('score', 0)


def play_game(variations, target_score=100000):
    """Play the game until the target score is reached."""
    with requests.Session() as session:  # Use a session to maintain cookies
        user_id, score = start_game(session)

        print(len(variations))

        while score < target_score:
            score = update_score(session, user_id, variations)
            time.sleep(0.333)  # 3 requests per second

        print(f"Target score reached! Final Score: {score}")


if __name__ == "__main__":
    variations = generate_variations("bugs_squashed")
    play_game(variations)
