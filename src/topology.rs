use crate::aliases::Pos;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Topology {
    descendants: Vec<u64>,
}

impl Default for Topology {
    fn default() -> Self {
        Self::new(&[4, 4, 4, 4])
    }
}

impl Topology {
    pub fn new(fanouts: &[u64]) -> Self {
        let mut leaves = fanouts.iter().product();
        let mut descendants = Vec::with_capacity(fanouts.len() + 2);

        descendants.push(0);
        for fanout in fanouts {
            descendants.push(leaves);
            leaves /= fanout;
        }
        descendants.push(1);

        Self { descendants }
    }

    pub fn height(&self) -> u64 {
        self.descendants.len() as u64
    }

    pub fn fanout(&self, level: u64) -> u64 {
        if level == 0 {
            0
        } else if level == self.height() as u64 {
            1
        } else {
            self.descendants[level as usize] / self.descendants[(level as usize) + 1]
        }
    }

    pub fn descendants(&self, level: u64) -> u64 {
        self.descendants[level as usize]
    }

    pub fn start(&self, node: Pos) -> u64 {
        if node.0 == 0 {
            0
        } else {
            node.1 * self.descendants[node.0 as usize]
        }
    }

    pub fn end(&self, node: Pos) -> u64 {
        if node.0 == 0 {
            0
        } else {
            self.start(node) + self.descendants[node.0 as usize]
        }
    }

    pub fn range(&self, node: Pos) -> Pos {
        (self.start(node), self.end(node))
    }

    pub fn offset(&self, leaf: u64, level: u64) -> u64 {
        if level == 0 {
            0
        } else {
            leaf / self.descendants[level as usize]
        }
    }

    pub fn is_ancestor(&self, n: Pos, m: Pos) -> bool {
        let (n_start, n_end) = self.range(n);
        let (m_start, m_end) = self.range(m);
        m != (0, 0) && (n == (0, 0) || (n_start <= m_start && m_end <= n_end))
    }

    pub fn leaf_position(&self, leaf: u64) -> Pos {
        (self.height() - 1, leaf)
    }

    pub fn path(&self, from: Pos, to: Pos) -> Path<'_> {
        Path::new(self, from, to)
    }

    pub fn coverage(&self, start: u64, end: u64) -> Coverage<'_> {
        Coverage::new(self, start, end)
    }
}

pub struct Path<'a> {
    from: Pos,
    to: Pos,
    topology: &'a Topology,
}

impl<'a> Path<'a> {
    pub fn new(topology: &'a Topology, from: Pos, to: Pos) -> Self {
        Self { topology, from, to }
    }
}

impl<'a> Iterator for Path<'a> {
    type Item = Pos;

    fn next(&mut self) -> Option<Self::Item> {
        (self.from.0 < self.to.0).then(|| {
            let leaf = self.topology.start(self.to);
            let level = self.from.0 + 1;
            let offset = self.topology.offset(leaf, level);
            self.from = (level, offset);
            self.from
        })
    }
}

pub struct Coverage<'a> {
    start: u64,
    end: u64,
    state: State,
    topology: &'a Topology,
}

enum State {
    Pre(u64),
    Intra,
    Post(u64),
}

impl<'a> Coverage<'a> {
    pub fn new(topology: &'a Topology, start: u64, end: u64) -> Self {
        Self {
            topology,
            start,
            end,
            state: State::Pre(topology.height() - 1),
        }
    }
}

impl<'a> Iterator for Coverage<'a> {
    type Item = Pos;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start > self.end {
            return None;
        }

        loop {
            match self.state {
                State::Pre(level) => {
                    if level < 2 {
                        self.state = State::Intra;
                    } else if self.start % self.topology.descendants(level - 1) != 0
                        && self.start + self.topology.descendants(level) <= self.end
                    {
                        let node = (level, self.topology.offset(self.start, level));
                        self.start += self.topology.descendants(level);
                        return Some(node);
                    } else {
                        self.state = State::Pre(level - 1);
                    }
                }
                State::Intra => {
                    if self.start + self.topology.descendants(1) <= self.end {
                        let node = (1, self.topology.offset(self.start, 1));
                        self.start += self.topology.descendants(1);
                        return Some(node);
                    } else {
                        self.state = State::Post(2);
                    }
                }
                State::Post(level) => {
                    if level >= self.topology.height() {
                        return None;
                    } else if self.start + self.topology.descendants(level) <= self.end {
                        let node = (level, self.topology.offset(self.start, level));
                        self.start += self.topology.descendants(level);
                        return Some(node);
                    } else {
                        self.state = State::Post(level + 1);
                    }
                }
            }
        }
    }
}

pub struct LeveledCoverage<'a> {
    level: u64,
    start: u64,
    end: u64,
    state: State,
    topology: &'a Topology,
}

impl<'a> LeveledCoverage<'a> {
    pub fn new(level: u64, start: u64, end: u64, topology: &'a Topology) -> Self {
        Self {
            level,
            start,
            end,
            state: State::Pre(topology.height() - 1),
            topology,
        }
    }
}

impl<'a> Iterator for LeveledCoverage<'a> {
    type Item = Pos;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start > self.end {
            return None;
        }

        loop {
            match self.state {
                State::Pre(level) => {
                    if level < self.level + 1 {
                        self.state = State::Intra;
                    } else if self.start % self.topology.descendants(level - 1) != 0
                        && self.start + self.topology.descendants(level) <= self.end
                    {
                        let pos = (level, self.topology.offset(self.start, level));
                        self.start += self.topology.descendants(level);
                        return Some(pos);
                    } else {
                        self.state = State::Pre(level - 1);
                    }
                }
                State::Intra => {
                    if self.start + self.topology.descendants(self.level) <= self.end {
                        let pos = (self.level, self.topology.offset(self.start, self.level));
                        self.start += self.topology.descendants(self.level);
                        return Some(pos);
                    } else {
                        self.state = State::Post(self.level + 1);
                    }
                }
                State::Post(level) => {
                    if level >= self.topology.height() {
                        return None;
                    } else if self.start + self.topology.descendants(level) <= self.end {
                        let pos = (level, self.topology.offset(self.start, level));
                        self.start += self.topology.descendants(level);
                        return Some(pos);
                    } else {
                        self.state = State::Post(level + 1);
                    }
                }
            }
        }
    }
}
