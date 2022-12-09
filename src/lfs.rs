use crate::raw::{GIT_LFS_AUTH_COMMAND_DOWNLOAD, git_remote_callbacks};
use crate::{RemoteCallbacks, util::Binding};
use serde::{Serialize, Deserialize};

/// 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfsAuthHdr {
    /// Auth token
    #[serde(rename = "Authorization")]
    pub authorization: String,
}

/// 
#[derive(Debug, Clone, Deserialize)]
pub struct LfsAuth {
    ///
    pub header: LfsAuthHdr,
    /// Lfs url
    pub href: String,
    /// 
    pub expires_in: u32,
}

///
pub struct LfsAuthenticate<'a> {
    /// 
    remote_callbacks: Option<&'a RemoteCallbacks<'a>>,
    /// 
    repo_url: String,
}

impl <'a> LfsAuthenticate<'a> {
    ///
    pub fn new(repo: &str) -> LfsAuthenticate<'a>  {
        crate::init();
        LfsAuthenticate {
            remote_callbacks: None,
            repo_url: repo.into()
        }
    }
    ///
    pub fn remote_callbacks(&mut self, remote_callbacks: &'a RemoteCallbacks<'a>) -> &mut Self {
        self.remote_callbacks = Some(&remote_callbacks);
        self
    }

    /// 
    pub fn auth(&self) -> Option<LfsAuth> {
        if let Some(callbacks) = &self.remote_callbacks {
            return self.auth_with(&callbacks.raw());
        }
        None
    }

    ///
    pub fn auth_with(&self, callbacks: &git_remote_callbacks) -> Option<LfsAuth> {
        let name = std::ffi::CString::new(self.repo_url.as_str()).unwrap();
        let mut buf = [0;4096];
        let ret = unsafe {
            crate::raw::git_lfs_authenticate(
                name.as_ptr(), 
                callbacks, 
                GIT_LFS_AUTH_COMMAND_DOWNLOAD, 
                buf.as_mut_ptr(), buf.len()
            )
        };
        if ret > 0 && ret < 4096 {
            return serde_json::from_slice(&buf[..ret as usize]).ok();
        } else {
            return None;
        }
    }
}