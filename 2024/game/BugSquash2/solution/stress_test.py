import concurrent.futures
import subprocess


# Function to execute the solve.py script
def run_solve():
    # Use subprocess to run the solve.py script
    result = subprocess.run(['python', 'solve.py'],
                            capture_output=True, text=True)
    return result.stdout


# Run the solve.py script 10 times concurrently
if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Create a list of 10 tasks to run solve.py concurrently
        futures = [executor.submit(run_solve) for _ in range(10)]

        # Wait for all the futures to complete and print the results
        for future in concurrent.futures.as_completed(futures):
            print(future.result())
