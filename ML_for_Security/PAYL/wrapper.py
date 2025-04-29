'''
    Wrapper script for CS 6262 Project 5
    run as : python wrapper.py for training mode
'''
import read_pcap as dpr
import random as rn
import sys
import analysis

# TASK A/B: Choose the protocol
training_protocol = "HTTP"
#OR 
#training_protocol = "DNS"
split_ratio = 0.75

# TASK B: Set the model parameters, when None they will default to the ML model's parameter search
http_smoothing_factor = .30
dns_smoothing_factor = .30
http_threshold_for_mahalanobis = 220
dns_threshold_for_mahalanobis = 70

def partition(payloads):
    # shuffle the data to randomly pick samples
    rn.shuffle(payloads)
    split_index = int(len(payloads) * split_ratio)
    training = payloads[0 : split_index + 1]
    test = payloads[split_index + 1 :len(payloads)]    
    return training, test

if __name__=='__main__':
    print(("Working with protocol: " + training_protocol + " : in training data."))
    attack_file = None
    
    # check which mode the program is being run in
    len_of_args = len(sys.argv)

    if(len_of_args == 1):
        print('\n\tAttack data not provided, training and testing model based on pcap files in \'data/\' folder alone.')
        print('\tTo provide attack data, run the code as: python wrapper.py <attack-data-file-name>')
    else:
        print(('\n\tAttack data provided, as command line argument \''+sys.argv[1]+'\''))
        attack_file = sys.argv[1]
    print('---------------------------------------------')
    payloads = dpr.getPayloadStrings(training_protocol)
    training, test = partition(payloads)
    
    # For HTTP training data, may need to ensure it includes large packet e.g.,
    # In the PAYL paper, 418, 730, 1460 are chosen
    # We need at least one min or max length samples in the training data set for HTTP
    
    if training_protocol == "HTTP":
        min_length = 0 
        max_length = 0
        while min_length == 0 or max_length == 0:    
            for x in training:
                if len(x) == 0:
                    min_length = 1
                if len(x) == 1460:
                    max_length = 1

            training, test = partition(payloads)

        for j in range(0, len(test)):        
            if len(test[j]) == 705:
                for i in range(0, len(training)):
                    if len(training[i]) != 0 and len(training[i]) != 1460 and len(training[i]) !=705:
                        t = training[i]
                        training[i] = test[j]
                        test[j] = t
                        break
                    
    # Simple sanity check
    if len(payloads) != len(test)+len(training) or split_ratio >= 1.0:
        sys.exit()
    else:
        '''
        To better understand the behaviour of the model with different parameters, 
        we typically let the parameters iterate over a range.
        Here, range(threshold_for_mahalanobis_lower, threshold_for_mahalanobis_upper+1) 
        is the range over which the mahalanobis threshold iterates. 

        Similarly, range(smoothing_factor_lower, smoothing_factor_upper+0.1) is the range over
        which the smoothing factor iterates.
    
        For each such combination of mahalanobis threshold and smoothing factor, the model is 
        generated with these parameters.

        '''
        # Configure the parameters, use the student-set model parameter if they are provided.
        if training_protocol.lower() == "http" and http_smoothing_factor is not None:
            smoothing_factor_lower = int(http_smoothing_factor * 10)  # multiplied by 10 because the parameter search uses range() to increment by 1 (/10 = 0.1)
            smoothing_factor_upper = int(http_smoothing_factor * 10)
        elif training_protocol.lower() == "dns" and dns_smoothing_factor is not None:
            smoothing_factor_lower = int(dns_smoothing_factor * 10)
            smoothing_factor_upper = int(dns_smoothing_factor * 10)
        else:
            smoothing_factor_lower = 3
            smoothing_factor_upper = 10

        if training_protocol.lower() == "http" and http_threshold_for_mahalanobis is not None:
            threshold_for_mahalanobis_lower = http_threshold_for_mahalanobis
            threshold_for_mahalanobis_upper = http_threshold_for_mahalanobis
        elif training_protocol.lower() == "dns" and dns_threshold_for_mahalanobis is not None:
            threshold_for_mahalanobis_lower = dns_threshold_for_mahalanobis
            threshold_for_mahalanobis_upper = dns_threshold_for_mahalanobis
        else:
            threshold_for_mahalanobis_lower = 20
            threshold_for_mahalanobis_upper = 9000

        # this loops from smoothing_factor_lower to smoothing_factor_upper in steps of 0.1
        for smoothing_factor in range(smoothing_factor_lower, smoothing_factor_upper+1):
            for mahabs in range(threshold_for_mahalanobis_lower,
                                threshold_for_mahalanobis_upper+1, 50):
                print(('Smoothing Factor: '+str(smoothing_factor/10.0)))
                print(('Threshold for Mahalanobis Distance: '+str(mahabs)))
                analysis.train_and_test(training, test, attack_file,
                                        smoothing_factor/10.0, mahabs, verbose = "False")
                print('---------------------------------------------')
