import random
import os
import sys
import json
import inspect

parent_dir = os.getcwd()
file_path = os.path.join(parent_dir,'TestOrchestrator4ML-main/detection/')
output_file_path = os.path.join(parent_dir,'fuzz_outputs.txt')

sys.path.append(file_path)

from main import get_test_details, checkClassificationAlgoTest, checkAccuracyTest, chackAttackTest, runDetectionTest

## Fuzzes passed method with values
def fuzzMethod(method,values):
    num_params = len(inspect.getargspec(method).args)
    error_output = []
    for value in values:
        try:
            if num_params == 1:
                method(value)
            elif num_params == 2:
                method(value,value)
            elif num_params == 4:
                method(value,None,None,None)
                method(None,value,None,None)
                method(None,None,value,None)
                method(None,None,None,value)
        except Exception as error:
            error_output.append("Error in {} with value {}: {}".format(method.__name__,value,error))

    return error_output

## Creates a list of 100 random integer values
def rand_ints():
    ints = [x for x in range(3,10000)]
    return random.sample(ints,100)

## Creates a list of random strings
def rand_strings():
    with open(os.path.join(parent_dir,'bad_strings.json'),'r') as f:
        data = json.load(f)
    return data

if __name__ == "__main__":
    methods = [get_test_details,checkClassificationAlgoTest,checkClassificationAlgoTest,checkAccuracyTest,chackAttackTest,runDetectionTest]

    fuzz_ints = rand_ints()
    fuzz_strings = rand_strings()

    output = []
    for method in methods:
        print(f'Fuzzing {method}...')
        output += fuzzMethod(method,fuzz_ints)
        output += fuzzMethod(method,fuzz_strings)

    print(f'Fuzz outputs written to {output_file_path}')
    
    with open(output_file_path,'w') as fp:
        for out in output:
            fp.write("%s\n" % out)


