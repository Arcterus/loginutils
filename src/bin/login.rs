extern crate isatty;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate pwhash;
extern crate termios;
extern crate users;

use std::io;
use std::io::{Read, Write};
use std::ffi::{CStr, CString};
use std::str;
use std::mem;
use libc::{EXIT_FAILURE, EXIT_SUCCESS};
use std::path::Path;
use std::process::{self, Command};
use std::os::unix::process::CommandExt;
use std::time::Duration;
use std::thread;
use std::fs::File;
use users::User;
use users::os::unix::UserExt;

const TIMEOUT: u32 = 60;
const ENV_USER: &str = "USER";
const ENV_LOGNAME: &str = "LOGNAME";
const ENV_HOME: &str = "HOME";
const ENV_SHELL: &str = "SHELL";

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn get_username() -> io::Result<String> {
    let nodename;
    unsafe {
        let mut utsname: libc::utsname = mem::uninitialized();
        cvt(libc::uname(&mut utsname))?;
        nodename = CStr::from_ptr(utsname.nodename.as_ptr())
            .to_string_lossy()
            .into_owned();
    }
    if nodename.is_empty() {
        print!("?");
    } else {
        print!("{}", nodename);
    }
    print!(" login: ");
    io::stdout().flush()?;

    let mut username = String::new();
    match io::stdin().read_line(&mut username) {
        Ok(_n) => Ok(String::from(username.trim())),
        Err(err) => Err(err),
    }
}

fn get_password() -> io::Result<String> {
    use termios::*;
    print!("Password: ");
    io::stdout().flush()?;

    // let old_termios;
    let mut termios = Termios::from_fd(libc::STDIN_FILENO)?;
    let old_termios = termios;

    termios.c_lflag &= !(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(libc::STDIN_FILENO, TCSANOW, &termios)?;

    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    println!();
    io::stdout().flush()?;

    tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &old_termios)?;

    Ok(String::from(password.trim()))
}

fn check_password(user: &User, password: &str) -> io::Result<bool> {
    let passwd = user.password();

    match passwd.as_ref() {
        // account is locked or no password
        "!" | "*" => Ok(false),
        // shadow password
        "x" => {
            let hash;

            unsafe {
                // XXX: this is not great
                let name = match CString::new(user.name()) {
                    Ok(name) => name,
                    Err(_) => process::exit(EXIT_FAILURE),
                };
                let spwd = libc::getspnam(name.as_ptr());
                if spwd.is_null() {
                    return Err(From::from(io::Error::last_os_error()));
                }
                hash = CStr::from_ptr((*spwd).sp_pwdp).to_string_lossy().to_owned();
            }

            Ok(pwhash::unix::verify(password, &hash))
        }
        // plain correct password
        passwd if passwd == password => Ok(true),
        // incorrect password
        _ => Ok(false),
    }
}

lazy_static! {
    // save original termios settings
    static ref INIT_TERMIOS: termios::Termios = {
        if !isatty::stdin_isatty() { panic!("Must be a terminal"); }
        termios::Termios::from_fd(libc::STDIN_FILENO).expect("Cannot get terminal attributes")
    };
}

extern "C" fn alarm_handler(
    _signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ptr: *mut libc::c_void,
) {
    // restore original termios settings
    termios::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &INIT_TERMIOS)
        .expect("Cannot set terminal attributes");
    println!("\r\nLogin timed out after {} seconds\r\n", TIMEOUT);
    match io::stdout().flush() {
        Ok(_) => unsafe { libc::_exit(EXIT_SUCCESS) },
        Err(_) => unsafe { libc::_exit(EXIT_FAILURE) },
    }
}

fn main() {
    unsafe {
        if libc::signal(libc::SIGALRM, alarm_handler as usize) == libc::SIG_ERR {
            libc::exit(EXIT_FAILURE);
        }
        libc::alarm(TIMEOUT);
    }
    enum State {
        U, // get username
        P, // get password
        C, // check password with username
        F, // failed and restart
        X, // exit
    }
    let mut username = String::new();
    let mut password = String::new();
    let mut state = State::U;
    let tries = 3;
    let mut failcount = 0;
    let mut user = User::new(0, "", 0);
    loop {
        if unsafe { libc::tcflush(0, libc::TCIFLUSH) } == -1 {
            process::exit(EXIT_FAILURE);
        }
        state = match state {
            State::U => match get_username() {
                Ok(ret) => {
                    username = ret;
                    if !username.is_empty() {
                        State::P
                    } else {
                        println!();
                        State::F
                    }
                }
                Err(_) => State::F,
            },
            State::P => match get_password() {
                Ok(ret) => {
                    password = ret;
                    match users::get_user_by_name(&username) {
                        Some(ret) => {
                            user = ret;
                            State::C
                        }
                        None => State::F,
                    }
                }
                Err(_) => State::F,
            },
            State::C => match check_password(&user, &password) {
                Ok(true) => {
                    println!("Login success");
                    break;
                }
                Ok(false) | Err(_) => State::F,
            },
            State::F => {
                thread::sleep(Duration::from_secs(3));
                println!("\nLogin incorrect");
                failcount += 1;
                if failcount < tries {
                    State::U
                } else {
                    eprintln!("max retries(3)");
                    State::X
                }
            }
            State::X => {
                process::exit(EXIT_FAILURE)
            }
        }
    }
    unsafe {
        libc::alarm(0);
    }

    let path = "/etc/nologin";
    if user.uid() != 0
            && unsafe { libc::access(CString::new(path).unwrap().as_ptr(), libc::R_OK) } == 0
    {
        let mut file = match File::open(&Path::new(path)) {
            Ok(file) => file,
            Err(_) => process::exit(EXIT_FAILURE),
        };
        let mut message = String::new();
        match file.read_to_string(&mut message) {
            Ok(0) => println!("nologin"),
            Ok(_) => println!("{}", message),
            Err(_) => process::exit(EXIT_FAILURE),
        }
        process::exit(EXIT_FAILURE)
    }

    let name = match CString::new(user.name()) {
        Ok(name) => name,
        Err(_) => process::exit(EXIT_FAILURE),
    };
    unsafe {
        if libc::initgroups(name.as_ptr(), user.primary_group_id()) == -1
            || libc::setgid(user.primary_group_id()) == -1
            || libc::setuid(user.uid()) == -1
        {
            process::exit(EXIT_FAILURE);
        }
    }

    let mut cmd = Command::new(user.shell());
    if user.home_dir().is_dir() {
        cmd.current_dir(user.home_dir());
    } else {
        println!(
            "bad $HOME: {}",
            user.home_dir().display()
        );
    }
    cmd.env(ENV_USER, user.name())
        .env(ENV_LOGNAME, user.name())
        .env(ENV_HOME, user.home_dir())
        .env(ENV_SHELL, user.shell());

    unsafe {
        if libc::signal(libc::SIGINT, libc::SIG_DFL) == libc::SIG_ERR {
            process::exit(EXIT_FAILURE);
        };

        // Message of the day
        if let Ok(mut file) = File::open("/etc/motd") {
            let mut message = String::new();
            if let Ok(_) = file.read_to_string(&mut message) {
                println!("{}", message);
            }
        }
    }

    cmd.exec();

    // exec() failed
    process::exit(EXIT_FAILURE)
}
