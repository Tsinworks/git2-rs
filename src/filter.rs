use crate::{
    raw::{
        git_filter, 
        git_buf, 
        git_filter_source, 
        git_writestream,
        git_filter_mode_t,
        git_error_code,
        git_blob,
        git_blob_rawcontent,
        git_blob_rawsize,
        git_filter_source_filemode, 
        git_filter_source_repo,
        git_filter_source_mode,
        git_filter_source_id, 
        git_filter_source_path, 
        git_filter_source_flags,
        git_repository_path, 
        git_repository_workdir,
        git_error_set_str,
        GIT_OK,
        GIT_DELAYED_STREAM,
    },
    util::Binding, 
    string_array::StringArray, 
    Oid,
    Buf, 
    Reference, 
    Error,
    Repository,
    Remote,
};
use crate::raw;
use std::marker::PhantomData;

/// Filter
pub trait Filter {
    /// version
    fn version(&self) -> u32;
    
    /// name
    fn name(&self) -> &str;

    /// attribute (nullable)
    fn attributes(&self) -> *const i8;

    ///  
    fn attrs_count(&self) -> isize;
    
    /// priority, 200 for driver
    fn priority(&self) -> i32;

    /// init
    fn init(&mut self) -> git_error_code;
    
    /// shutdown
    fn shutdown(&mut self);
    
    ///
    fn sync_begin(&mut self);
    
    ///
    fn sync_end(&mut self);

    /// check attribute?
    fn check<'repo>(&mut self, attrs: Option<&[&str]>, fs: &FilterSource<'repo>, payload: *mut *mut u8) -> git_error_code;
    
    /// check attribute?
    fn prefilter<'repo>(&mut self, attrs: Option<&[&str]>, blob: &[u8], fs: &FilterSource<'repo>, payload: *mut *mut u8) -> git_error_code;

    /// apply
    fn apply<'repo>(&mut self, to: &mut Buf, from: &Buf, fs: &FilterSource<'repo>, payload: *mut *mut u8) -> git_error_code;

    /// stream
    fn stream<'repo>(&mut self, fs: &FilterSource<'repo>, next: Option<WriteStream>, payload: *mut *mut u8) -> Result<Box<dyn Stream>, Error>;

    /// clean up
    fn cleanup(&mut self, payload: *mut u8);
}

/// Filter source
pub struct FilterSource<'repo> {
    raw: *const git_filter_source,
    _marker: PhantomData<&'repo Repository>
}

impl <'repo> Binding for FilterSource<'repo> {
    type Raw = *const git_filter_source;
    /// 
    unsafe fn from_raw(raw: Self::Raw) -> Self {
        Self {
            raw,
            _marker: PhantomData
        }
    }
    /// 
    fn raw(&self) -> Self::Raw {
        self.raw
    }
}

impl <'repo> FilterSource<'repo> {
    /// Get repository head
    pub fn head(&self) -> Result<Reference<'repo>, Error> {
        unsafe {
            let mut ptr = std::ptr::null_mut();
            let repo = git_filter_source_repo(self.raw());
            try_call!(raw::git_repository_head(&mut ptr, repo));
            Ok(Binding::from_raw(ptr))
        }
    }

    /// get remote name by ref
    pub fn remote(&self, refname: &str) -> Result<Buf, Error>  {
        let refname = std::ffi::CString::new(refname)?;
        unsafe {
            let buf = Buf::new();
            let repo = git_filter_source_repo(self.raw());
            try_call!(raw::git_branch_remote_name(buf.raw(), repo, refname));
            Ok(buf)
        }
    }

    /// Lookup remote
    pub fn lookup_remote(&self, name: &str) -> Result<Remote<'repo>, Error> {
        let mut ret = std::ptr::null_mut();
        let name = std::ffi::CString::new(name)?;
        unsafe {
            let repo = git_filter_source_repo(self.raw());
            try_call!(raw::git_remote_lookup(&mut ret, repo, name));
            Ok(Binding::from_raw(ret))
        }
    }

    /// List remotes
    pub fn remotes(&self) -> Result<StringArray, Error>  {
        let mut arr = raw::git_strarray {
            strings: std::ptr::null_mut(),
            count: 0,
        };
        unsafe {
            let repo = git_filter_source_repo(self.raw());
            try_call!(raw::git_remote_list(&mut arr, repo));
            Ok(Binding::from_raw(arr))
        }
    }

    /// Get repo path
    pub fn repo_path(&self) -> Option<&str> {
        unsafe {
            let repo = git_filter_source_repo(self.raw());
            std::ffi::CStr::from_ptr(git_repository_path(repo)).to_str().ok()
        }
    }

    /// Get repo working dir
    pub fn repo_workdir(&self) -> Option<&str> {
        unsafe {
            let repo = git_filter_source_repo(self.raw());
            std::ffi::CStr::from_ptr(git_repository_workdir(repo)).to_str().ok()
        }
    }

    /// Filter mode
    pub fn mode(&self) -> git_filter_mode_t {
        unsafe { git_filter_source_mode(self.raw) }
    }

    /// Filter id
    pub fn id(&self) -> Oid {
        unsafe { Binding::from_raw(git_filter_source_id(self.raw)) }
    }

    /// Filter path
    pub fn path(&self) -> Option<&str> {
        unsafe { std::ffi::CStr::from_ptr(git_filter_source_path(self.raw)).to_str().ok() }
    }

    /// Filter flags
    pub fn flags(&self) -> u32 {
        unsafe { git_filter_source_flags(self.raw) }
    }
    
    /// Filter file mode
    pub fn file_mode(&self) -> u16 {
        unsafe { git_filter_source_filemode(self.raw) }
    }
}

extern "C" fn flt_init(flt: *mut git_filter) -> i32 {
    let rflt: *mut RawFilter = flt as _;
    unsafe { &mut *rflt }.inner.init()
}

extern "C" fn flt_shutdown(flt: *mut git_filter) {
    let rflt: *mut RawFilter = flt as _;
    unsafe { &mut *rflt }.inner.shutdown();
}

extern "C" fn flt_check(
    flt: *mut git_filter, 
    payload: *mut *mut u8, 
    src:*const git_filter_source, 
    attrs:*const *const i8
) -> git_error_code 
{
    let rflt: *mut RawFilter = flt as _;
    let mut attr_vec = vec![];
    if !attrs.is_null() {
        for i in 0..unsafe { &mut *rflt }.inner.attrs_count() {
            unsafe {
                let ptr = *(attrs.offset(i));
                if ptr.is_null() {
                    break;
                }
                attr_vec.push(std::ffi::CStr::from_ptr(ptr).to_str().unwrap());
            }
        }
    }

    unsafe {
        { &mut *rflt }.inner.check(
            if attr_vec.len() == 0 { None }
            else{ Some(&attr_vec) },
            &FilterSource::from_raw(src),
            payload
        )
    }
}

extern "C" fn flt_prefilter(
    flt: *mut git_filter, 
    payload: *mut *mut u8, 
    src:*const git_filter_source, 
    blob: *const git_blob,
    attrs:*const *const i8
) -> git_error_code 
{
    let rflt: *mut RawFilter = flt as _;
    let mut attr_vec = vec![];
    if !attrs.is_null() {
        for i in 0..unsafe { &mut *rflt }.inner.attrs_count() {
            unsafe {
                let ptr = *(attrs.offset(i));
                if ptr.is_null() {
                    break;
                }
                attr_vec.push(std::ffi::CStr::from_ptr(ptr).to_str().unwrap());
            }
        }
    }

    unsafe {
        let blob = std::slice::from_raw_parts(git_blob_rawcontent(blob) as *const u8, git_blob_rawsize(blob) as _);
        { &mut *rflt }.inner.prefilter(
            if attr_vec.len() == 0 { None }
            else{ Some(&attr_vec) },
            blob,
            &FilterSource::from_raw(src),
            payload
        )
    }
}

extern "C" fn flt_apply(
    flt: *mut git_filter,
    payload: *mut *mut u8, 
    to: *mut git_buf,
    from: *const git_buf,
    src: *const git_filter_source
) -> git_error_code 
{
    let to = to as *mut Buf;
    let from = from as *const Buf;
    let rflt: *mut RawFilter = flt as _;
    unsafe { (&mut *rflt).inner.apply(&mut *to, &*from, &FilterSource::from_raw(src), payload) }
}

/*
struct compress_stream {
	git_writestream parent;
	git_writestream *next;
	git_filter_mode_t mode;
	char current;
	size_t current_chunk;
};

    pub write: Option<extern "C" fn(*mut git_writestream, *const c_char, size_t) -> c_int>,
    pub close: Option<extern "C" fn(*mut git_writestream) -> c_int>,
    pub free: Option<extern "C" fn(*mut git_writestream)>,
*/

/// Git write stream
pub trait Stream: std::io::Write {
    /// close stream
    fn close(&mut self) -> i32;


}

#[repr(C)]
pub(crate) struct WriteStreamWrapper {
    raw: git_writestream,
    inner: Box<dyn Stream>,
}

/// 
pub struct WriteStream {
    raw: *mut git_writestream
}

impl std::io::Write for WriteStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe { 
            match &{&mut *(self.raw)}.write {
                Some(write) => {
                    let ret = write(self.raw, buf.as_ptr() as _, buf.len());
                    if ret == 0 {
                        Ok(buf.len())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                },
                None => {
                    Ok(0)
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Stream for WriteStream {
    fn close(&mut self) -> i32 {
        unsafe { 
            match &{&mut *(self.raw)}.close {
                Some(close) => {
                    close(self.raw)
                },
                None => {
                    0
                }
            }
        }
    }
}

extern "C" fn stream_write(stream: *mut git_writestream, data: *const libc::c_char, size: libc::size_t) -> libc::c_int {
    let st: *mut WriteStreamWrapper = stream as _;
    let buf = unsafe {std::slice::from_raw_parts(data as *const u8, size)};
    unsafe {&mut *st}.inner.write(&buf).map_or_else(|e| {
        let msg = std::ffi::CString::new(e.to_string()).unwrap();
        unsafe { git_error_set_str(raw::GIT_ERROR, msg.as_ptr()); }
        raw::GIT_ERROR
    }, |s| s as _)
}

extern "C" fn stream_close(stream: *mut git_writestream) -> libc::c_int {
    let st: *mut WriteStreamWrapper = stream as _;
    unsafe {&mut *st}.inner.close()
}

extern "C" fn stream_free(stream: *mut git_writestream) {
    let st: *mut WriteStreamWrapper = stream as _;
    unsafe {
        let rst = Box::from_raw(st);
        drop(rst);
    }
}

extern "C" fn flt_stream(
    out: *mut *mut git_writestream,
    flt: *mut git_filter,
    payload: *mut *mut u8, 
    src: *const git_filter_source,
    next: *mut git_writestream,
) -> git_error_code {
    let rflt: *mut RawFilter = flt as _;
    let next = if next.is_null() {
        None
    } else {
        Some(WriteStream{ raw: next })
    };
    unsafe { 
        (&mut *rflt).inner.stream(&FilterSource::from_raw(src), next, payload) 
    }.map_or_else(|e| {
        let msg = std::ffi::CString::new(e.to_string()).unwrap();
        unsafe { git_error_set_str(raw::GIT_ERROR, msg.as_ptr()); }
        e.raw_code()
    }, |inner| {
        let stream = WriteStreamWrapper {
            raw: git_writestream { 
                write: Some(stream_write), 
                close: Some(stream_close), 
                free: Some(stream_free) 
            },
            inner,
        };
        let ptr: *mut git_writestream = Box::into_raw(Box::new(stream)) as _;
        unsafe { *out = ptr };
        if !unsafe {*payload}.is_null() {
            GIT_DELAYED_STREAM
        } else {
            GIT_OK
        }
    })
}

extern "C" fn flt_cleanup(
    flt: *mut git_filter,
    payload: *mut u8
) {
    let rflt: *mut RawFilter = flt as _;
    unsafe { &mut *rflt }.inner.cleanup(payload);
}

extern "C" fn flt_sync_begin(
    flt: *mut git_filter
) {
    let rflt: *mut RawFilter = flt as _;
    unsafe { &mut *rflt }.inner.sync_begin();
}

extern "C" fn flt_sync_end(
    flt: *mut git_filter
) {
    let rflt: *mut RawFilter = flt as _;
    unsafe { &mut *rflt }.inner.sync_end();
}

#[repr(C)]
pub struct RawFilter {
    _raw: git_filter,
    inner: Box<dyn Filter>
}

impl RawFilter {
    pub fn new(inner: Box<dyn Filter>) -> Self {
        RawFilter { 
            _raw: git_filter {
                version: inner.version(),
                attributes: inner.attributes(),
                initialize: Some(flt_init),
                shutdown: Some(flt_shutdown),
                begin_sync: Some(flt_sync_begin),
                end_sync: Some(flt_sync_end),
                check: None,
                prefilter: Some(flt_prefilter),
                apply: Some(flt_apply),
                stream: Some(flt_stream),
                cleanup: Some(flt_cleanup),
            }, 
            inner
        }
    }

    fn priority(&self) -> i32 {
        self.inner.priority()
    }
}

impl Drop for RawFilter {
    fn drop(&mut self) {
        let cstr = std::ffi::CString::new(self.inner.name()).unwrap();
        unsafe { crate::raw::git_filter_unregister(cstr.as_ptr()); }    
    }
}

pub(crate) fn create_filter(flt: Box<dyn Filter>) -> Box<RawFilter> {
    let mut raw_filter = Box::new(RawFilter::new(flt));
    unsafe {
        let cstr = std::ffi::CString::new(raw_filter.inner.name()).unwrap();
        let priority = raw_filter.priority();
        let raw_flt = &mut *raw_filter;
        crate::raw::git_filter_register( cstr.as_ptr(), std::mem::transmute(raw_flt), priority);
    }
    raw_filter
}