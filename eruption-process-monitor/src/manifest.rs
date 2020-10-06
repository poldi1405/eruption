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

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

type Result<T> = std::result::Result<T, eyre::Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    exe_file: String,
    checksum: String,
    version: i32,
    parameters: Vec<Parameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    name: String,
    description: String,
    location: usize,
    default_color: u32,
}

impl Manifest {
    pub fn new<P: AsRef<Path>>(filename: P) -> Result<Self> {
        let s = fs::read_to_string(filename.as_ref())?;
        let result = serde_yaml::from_str(&s)?;

        println!("{:#?}", result);

        Ok(result)
    }

    pub fn save<P: AsRef<Path>>(&self, filename: P) -> Result<()> {
        let mut hasher = Sha1::new();

        let file = fs::read(&Path::new(&self.exe_file))?;
        hasher.input(&file);

        let hex = hasher.result_str();

        let result = Manifest {
            exe_file: self.exe_file.clone(),
            checksum: hex,
            version: self.version,
            parameters: self.parameters.clone(),
        };

        let result = serde_yaml::to_string(&result).unwrap();
        fs::write(filename.as_ref(), result)?;

        Ok(())
    }
}
