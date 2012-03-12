#!/bin/sh
#
# Copyright 2008-2012 Concur Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

rm -f tripit_erlang_v1_*.tgz
rm -f tripit_erlang_v1_*.zip
mkdir tripit_erlang_v1
cp *.erl tripit_erlang_v1
tar czvf tripit_erlang_v1.tgz tripit_erlang_v1/*
zip tripit_erlang_v1.zip tripit_erlang_v1/*
rm -rf tripit_erlang_v1
