// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#pragma once

struct gpu_alloc_request_t {
  uint64_t ptr_addr;
  size_t size;
};

struct gpu_alloc_info_t {
    pid_t pid;
    pid_t tid;
    uint64_t alloc_addr;
    size_t size;
    uint64_t timestamp;
};
