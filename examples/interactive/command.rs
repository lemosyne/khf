use anyhow::Error;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::multispace0,
    combinator::{map, map_res},
    sequence::{delimited, tuple},
    IResult,
};
use std::str::FromStr;

pub enum Command {
    Derive(u64),
    Update(u64),
    Commit,
    Invalid,
    Clear,
    Truncate(u64),
}

impl FromStr for Command {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(parse_cmd(s).map(|(_, cmd)| cmd).unwrap_or(Command::Invalid))
    }
}

pub fn parse_cmd(input: &str) -> IResult<&str, Command> {
    alt((derive_cmd, update_cmd, commit_cmd, clear_cmd, truncate_cmd))(input)
}

fn derive_cmd(input: &str) -> IResult<&str, Command> {
    map(
        tuple((
            multispace0,
            tag("derive"),
            multispace0,
            map_res(is_not(" \t"), |key| u64::from_str(key)),
            multispace0,
        )),
        |(_, _, _, key, _)| Command::Derive(key),
    )(input)
}

fn update_cmd(input: &str) -> IResult<&str, Command> {
    map(
        tuple((
            multispace0,
            tag("update"),
            multispace0,
            map_res(is_not(" \t"), |key| u64::from_str(key)),
            multispace0,
        )),
        |(_, _, _, key, _)| Command::Update(key),
    )(input)
}

fn commit_cmd(input: &str) -> IResult<&str, Command> {
    map(delimited(multispace0, tag("commit"), multispace0), |_| {
        Command::Commit
    })(input)
}

fn clear_cmd(input: &str) -> IResult<&str, Command> {
    map(delimited(multispace0, tag("clear"), multispace0), |_| {
        Command::Clear
    })(input)
}

fn truncate_cmd(input: &str) -> IResult<&str, Command> {
    map(
        tuple((
            multispace0,
            tag("truncate"),
            multispace0,
            map_res(is_not(" \t"), |key| u64::from_str(key)),
            multispace0,
        )),
        |(_, _, _, keys, _)| Command::Truncate(keys),
    )(input)
}
