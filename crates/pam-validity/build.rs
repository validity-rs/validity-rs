//! Links the module with `-z nodelete`.
//!
//! libpam unloads its modules in `pam_end`. zbus and zruntime may leave a
//! short-lived thread finishing work (a connection's last messages, a match
//! rule removal) after `pam_sm_authenticate` returns; unmapping the module
//! under it would crash the application. With `nodelete`, `dlclose` leaves
//! the module mapped until the process exits, and loading it again reuses it.

fn main() {
    println!("cargo::rustc-cdylib-link-arg=-Wl,-z,nodelete");
}
