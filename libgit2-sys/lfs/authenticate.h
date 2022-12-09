#ifndef INCLUDE_git_lfs_authenticate_h__
#define INCLUDE_git_lfs_authenticate_h__
#pragma once

#include "git2/common.h"
#include "git2/remote.h"

GIT_BEGIN_DECL

typedef enum git_lfs_command {
    git_lfs_command_download,
    git_lfs_command_upload,
} git_lfs_command_t;

GIT_EXTERN(int) git_lfs_authenticate(const char* repo_url, git_remote_callbacks *t, git_lfs_command_t command, char* buffer, size_t size);

GIT_END_DECL

#endif