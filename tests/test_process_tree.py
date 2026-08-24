from ebpfdet.events import EventType, ProcessEvent
from ebpfdet.process_tree import ProcessTree


def _ev(t, pid, ppid, comm, **kw):
    return ProcessEvent(EventType(t), pid, ppid, comm, **kw)


def test_ancestry_chain():
    tree = ProcessTree()
    for e in [_ev("exec", 1, 0, "init"), _ev("fork", 2, 1, "init"),
              _ev("exec", 2, 1, "nginx"), _ev("fork", 3, 2, "nginx"),
              _ev("exec", 3, 2, "sh")]:
        tree.apply(e)
    chain = [n.comm for n in tree.ancestry(3)]
    assert chain == ["sh", "nginx", "init"]


def test_has_ancestor():
    tree = ProcessTree()
    for e in [_ev("exec", 10, 0, "nginx"), _ev("exec", 20, 10, "sh")]:
        tree.apply(e)
    assert tree.has_ancestor(20, "nginx")
    assert not tree.has_ancestor(20, "sshd")


def test_dropped_parent_becomes_synthetic():
    # we never saw pid 10's exec (dropped); pid 20 references it as parent
    tree = ProcessTree()
    tree.apply(_ev("exec", 20, 10, "sh"))
    parent = tree.get(10)
    assert parent is not None and parent.synthetic


def test_exec_over_keeps_ancestry():
    tree = ProcessTree()
    tree.apply(_ev("fork", 5, 1, "bash"))
    tree.apply(_ev("exec", 5, 1, "python"))   # exec-over
    node = tree.get(5)
    assert node.comm == "python" and node.ppid == 1


def test_reap_dead_leaves():
    tree = ProcessTree()
    tree.apply(_ev("exec", 1, 0, "init"))
    tree.apply(_ev("fork", 2, 1, "init"))
    tree.apply(_ev("exit", 2, 1, "init"))
    assert tree.reap_dead() == 1
    assert tree.get(2) is None
    assert tree.get(1) is not None   # alive parent kept


def test_cycle_safe_ancestry():
    tree = ProcessTree()
    tree.apply(_ev("exec", 1, 1, "weird"))   # self-parent
    assert len(tree.ancestry(1)) == 1        # does not loop forever
