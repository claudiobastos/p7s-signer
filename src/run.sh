#!/bin/bash

export CERTIFICATE_PATH=./fake.pem
export PRIVATE_KEY_PATH=./fake-private.key

export INPUT_PATH=./input.txt
export OUTPUT_PATH=./output.p7s

go run .

