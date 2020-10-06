/*
    This file is part of Eruption.

    Eruption is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Eruption is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Eruption.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::fmt;
use std::path::Path;

type Result<T> = std::result::Result<T, eyre::Error>;

#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    #[error("Operation fehlgeschlagen")]
    OpFailed {},
}

pub struct HexSlice<'a>(pub &'a [u8]);

impl<'a> HexSlice<'a> {
    pub fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "0x{:02x}, ", byte)?;
        }
        Ok(())
    }
}

pub fn get_process_file_name(pid: i32) -> Result<String> {
    let tmp = format!("/proc/{}/exe", pid);
    let filename = Path::new(&tmp);
    let result = nix::fcntl::readlink(filename);

    Ok(result
        .map_err(|_| UtilError::OpFailed {})?
        .into_string()
        .map_err(|_| UtilError::OpFailed {})?)
}
