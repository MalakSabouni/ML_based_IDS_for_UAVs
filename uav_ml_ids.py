#!/usr/bin/env python3
import sys
from nfstream import NFStreamer, NFPlugin
import pickle
import warnings
import pandas as pd
import time
from datetime import datetime


class ModelPrediction(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.model_prediction = 0

    def on_expire(self, flow):
        headers1_phase1 = [
            'bidirectional_psh_packets',
            'bidirectional_rst_packets',
            'bidirectional_fin_packets',
            'src2dst_syn_packets',
            'src2dst_cwr_packets',
            'src2dst_ece_packets',
            'src2dst_urg_packets',
            'src2dst_ack_packets',
            'src2dst_psh_packets',
            'src2dst_rst_packets',
            'src2dst_fin_packets',
            'dst2src_syn_packets',
            'dst2src_cwr_packets',
            'dst2src_ece_packets',
            'dst2src_urg_packets',
            'dst2src_ack_packets',
            'dst2src_psh_packets',
            'dst2src_rst_packets',
            'dst2src_fin_packets',
            'application_is_guessed',
            'application_confidence',
            'splt_direction_1',
            'splt_direction_2',
            'splt_direction_3',
            'splt_ps_1',
            'splt_ps_2',
            'splt_ps_3',
            'splt_piat_ms_1',
            'splt_piat_ms_2',
            'splt_piat_ms_3']
        values_phase1 = [
            flow.bidirectional_psh_packets,
            flow.bidirectional_rst_packets,
            flow.bidirectional_fin_packets,
            flow.src2dst_syn_packets,
            flow.src2dst_cwr_packets,
            flow.src2dst_ece_packets,
            flow.src2dst_urg_packets,
            flow.src2dst_ack_packets,
            flow.src2dst_psh_packets,
            flow.src2dst_rst_packets,
            flow.src2dst_fin_packets,
            flow.dst2src_syn_packets,
            flow.dst2src_cwr_packets,
            flow.dst2src_ece_packets,
            flow.dst2src_urg_packets,
            flow.dst2src_ack_packets,
            flow.dst2src_psh_packets,
            flow.dst2src_rst_packets,
            flow.dst2src_fin_packets,
            flow.application_is_guessed,
            flow.application_confidence,
            flow.splt_direction[0],
            flow.splt_direction[1],
            flow.splt_direction[2],
            flow.splt_ps[0],
            flow.splt_ps[1],
            flow.splt_ps[2],
            flow.splt_piat_ms[0],
            flow.splt_piat_ms[1],
            flow.splt_piat_ms[2]]
        # print(values)
        # Create a dictionary with headers as keys and values as values
        data = dict(zip(headers1_phase1, values_phase1))

        # Convert the dictionary to a DataFrame
        df = pd.DataFrame(data, index=[0])
        normalized_values = self.scaler_model.transform(df)

        flow.udps.model_prediction = self.novelty_model.predict(
            normalized_values)
        if (flow.udps.model_prediction[0] == 1):
            self.log_process("Traffic seems benign so far")
        elif (flow.udps.model_prediction[0] == -1):
            self.log_process("potential malicious traffic detected!")
            self.on_malicious(flow)

    def on_malicious(self, flow):
        headers1_phase2 = [
            'expiration_id', 'src_port', 'dst_port', 'protocol',
            'bidirectional_duration_ms', 'bidirectional_packets',
            'bidirectional_bytes', 'src2dst_duration_ms', 'src2dst_packets',
            'src2dst_bytes', 'dst2src_last_seen_ms', 'bidirectional_stddev_ps',
            'bidirectional_max_ps', 'src2dst_stddev_ps', 'src2dst_max_ps',
            'bidirectional_stddev_piat_ms', 'src2dst_stddev_piat_ms',
            'application_confidence', 'splt_direction_2', 'splt_direction_3']
        values_phase2 = [
            flow.expiration_id,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.bidirectional_duration_ms,
            flow.bidirectional_packets,
            flow.bidirectional_bytes,
            flow.src2dst_duration_ms,
            flow.src2dst_packets,
            flow.src2dst_bytes,
            flow.dst2src_last_seen_ms,
            flow.bidirectional_stddev_ps,
            flow.bidirectional_max_ps,
            flow.src2dst_stddev_ps,
            flow.src2dst_max_ps,
            flow.bidirectional_stddev_piat_ms,
            flow.src2dst_stddev_piat_ms,
            flow.application_confidence,
            flow.splt_direction[1],
            flow.splt_direction[2]]

        # Create a dictionary with headers as keys and values as values
        data = dict(zip(headers1_phase2, values_phase2))

        # Convert the dictionary to a DataFrame
        df = pd.DataFrame(data, index=[0])
        normalized_values2 = self.scaler_model2.transform(df)

        # classify the attack type with the second model
        flow.udps.model_prediction = self.classify_model.predict(
            normalized_values2)

        if (flow.udps.model_prediction[0] == 0):
            self.log_process(
                "Detected s possibility of a Denial of Service attack")
        elif (flow.udps.model_prediction[0] == 1):
            self.log_process("Detected a possibility of hijack control attack")
        elif (flow.udps.model_prediction[0] == 2):
            self.log_process(
                "Detected a possibility of Man-In-The-Middle attack")
        else:
            self.log_process("uncertain attack")

    def log_process(self, msg):
        date = str(datetime.now())
        log_msg = msg + " at " + date
        print(log_msg)
        file_path = 'logs/traffic_logs'
        with open(file_path, 'a') as file:
            file.write(log_msg + "\n")


if __name__ == '__main__':
    # Ignore warning messages
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    warnings.filterwarnings("ignore", category=UserWarning)
    # Load the model from the pickle file
    with open('models/phase_1_model.pkl', 'rb') as f:
        model1 = pickle.load(f)
    with open('models/phase2_model.pkl', 'rb') as f1:
        model2 = pickle.load(f1)
    with open('models/standard_scaler1.pkl', 'rb') as f2:
        scaler = pickle.load(f2)
    with open('models/standard_scaler_2.pkl', 'rb') as f3:
        scaler2 = pickle.load(f3)

# (ip src net 192.168.10.0/24) and (ip dst net 192.168.10.0/24)
    while True:
        my_streamer = NFStreamer(
            source="wlan0mon",
            bpf_filter="(ip src net 192.168.10.0/24) and (ip dst net 192.168.10.0/24)",
            promiscuous_mode=True,
            udps=ModelPrediction(
                novelty_model=model1,
                classify_model=model2,
                scaler_model=scaler,
                scaler_model2=scaler2),
            idle_timeout=5,
            active_timeout=5,
            accounting_mode=0,
            n_dissections=1,
            statistical_analysis=True,
            splt_analysis=3,
            n_meters=0,
            max_nflows=10,
            performance_report=0,
            system_visibility_mode=0,
            system_visibility_poll_ms=1000)

        for flow in my_streamer:
            flow.udps.model_prediction
        time.sleep(3)
