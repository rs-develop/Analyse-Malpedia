#!/usr/bin/python
import argparse
import os

from elasticsearch import Elasticsearch
from elastic_mappings import malpedia_sample_mapping, malpedia_family_mapping, malpedia_rel_data_mapping


def create_index(elastic_obj, index_name, mapping_name):

    # if an old index exists, detete it
    elastic_obj.options(ignore_status=[400,404]).indices.delete(index=index_name)
    elastic_obj.indices.create(
        index=index_name,
        body=mapping_name
    )

    # create index
    elastic_obj.options(ignore_status=[400,404]).indices.delete(index=index_name)
    elastic_obj.indices.create(
        index=index_name,
        body=mapping_name
    )

def upload_data(elastic_obj, file_path, index_name):

    with open(file_path,'r') as file:
        i = 1
        # Write malpedia data
        for record in file.readlines():
            elastic_obj.index(index=index_name, id=i, document=record)
            print("Writing record", i , "of", file_path)
            i = i + 1

if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='Upload Malpedia analysis to elastic')
    parser.add_argument('root_path_to_reports', help="Path to the directory which contains the analyse Malpedia reports")
    parser.add_argument('elastic_ip', help='IP to elastic, for example: 10.10.10.250', type=str)

    args=parser.parse_args()

    elastic_obj = Elasticsearch('http://' + args.elastic_ip +':9200')

    # Created index
    create_index(elastic_obj, 'malpedia_sample_data', malpedia_sample_mapping)
    create_index(elastic_obj, 'malpedia_family_data', malpedia_family_mapping)
    create_index(elastic_obj, 'malpedia_rel_data', malpedia_rel_data_mapping)

    # Upload data
    upload_data(elastic_obj, args.root_path_to_reports + os.sep + 'malpedia_sample_analysis.json', 'malpedia_sample_data')
    upload_data(elastic_obj, args.root_path_to_reports + os.sep + 'malpedia_family_analysis.json', 'malpedia_family_data')
    upload_data(elastic_obj, args.root_path_to_reports + os.sep + 'malpedia_relative_analysis.json', 'malpedia_rel_data')
