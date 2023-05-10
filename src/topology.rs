use crate::aliases::Pos;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Topology<O> {
    descendants: Vec<O>,
}

impl<O> Default for Topology<O> {
    fn default() -> Self {
        Self::new(&[4, 4, 4, 4])
    }
}

impl<O> Topology<O>
where
    O: PrimInt,
{
    pub fn new(fanouts: &[O]) -> Self {
        let mut leaves = fanouts.iter().product();
        let mut descendants = Vec::with_capacity(fanouts.len() + 2);

        descendants.push(O::zero());
        for fanout in fanouts {
            descendants.push(leaves);
            leaves /= fanout;
        }
        descendants.push(O::one());

        Self { descendants }
    }

    pub fn height(&self) -> usize {
        self.descendants.len()
    }

    pub fn fanout(&self, level: usize) -> O {
        if level == 0 {
            O::zero()
        } else if level == self.height() {
            O::one()
        } else {
            self.descendants[level] / self.descendants[level + 1]
        }
    }

    pub fn descendants(&self, level: usize) -> O {
        self.descendants[level]
    }

    pub fn start(&self, node: Pos<O>) -> O {
        if node.0 == 0 {
            O::zero()
        } else {
            node.1 * self.descendants[node.0]
        }
    }

    pub fn end(&self, node: Pos<O>) -> O {
        if node.0 == 0 {
            O::zero()
        } else {
            self.start(node) + self.descendants[node.0]
        }
    }

    pub fn range(&self, node: Pos<O>) -> (O, O) {
        (self.start(node), self.end(node))
    }

    pub fn offset(&self, leaf: O, level: usize) -> O {
        if level == 0 {
            O::zero()
        } else {
            leaf / self.descendants[level]
        }
    }

    pub fn is_ancestor(&self, n: Pos<O>, m: Pos<O>) -> bool {
        let (n_start, n_end) = self.range(n);
        let (m_start, m_end) = self.range(m);
        m != (0, 0) && (n == (0, 0) || (n_start <= m_start && m_end <= n_end))
    }

    pub fn leaf_position(&self, leaf: O) -> Pos<O> {
        (self.height() - 1, leaf)
    }

    pub fn path(&self, from: Pos<O>, to: Pos<O>) -> Path<'_, O> {
        Path::new(self, from, to)
    }

    pub fn coverage(&self, start: O, end: O) -> Coverage<'_, O> {
        Coverage::new(self, start, end)
    }
}

pub struct Path<'a, O> {
    from: Pos<O>,
    to: Pos<O>,
    topology: &'a Topology<O>,
}

impl<'a, O> Path<'a, O> {
    pub fn new(topology: &'a Topology<O>, from: Pos<O>, to: Pos<O>) -> Self {
        Self { topology, from, to }
    }
}

impl<'a, O> Iterator for Path<'a, O>
where
    O: PrimInt,
{
    type Item = Pos<O>;

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

pub struct Coverage<'a, O> {
    start: O,
    end: O,
    state: State<O>,
    topology: &'a Topology<O>,
}

enum State<O> {
    Pre(O),
    Intra,
    Post(O),
}

impl<'a, O> Coverage<'a, O>
where
    O: PrimInt,
{
    pub fn new(topology: &'a Topology<O>, start: O, end: O) -> Self {
        Self {
            topology,
            start,
            end,
            state: State::Pre(topology.height() - 1),
        }
    }
}

impl<'a, O> Iterator for Coverage<'a, O>
where
    O: PrimInt,
{
    type Item = Pos<O>;

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
