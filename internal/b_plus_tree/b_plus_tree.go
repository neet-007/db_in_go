package b_plus_tree

import (
	"bytes"
	"db_in_go/internal/utils"
	"encoding/binary"
	"fmt"
)

/*
	A node includes:

	A fixed-size header, which contains:
	The type of node (leaf or internal).
	The number of keys.
	A list of pointers to child nodes for internal nodes.
	A list of KV pairs.
	A list of offsets to KVs, which can be used to binary search KVs.
	| type | nkeys |  pointers  |   offsets  | key-values | unused |
	|  2B  |   2B  | nkeys * 8B | nkeys * 2B |     ...    |        |
	This is the format of each KV pair. Lengths followed by data.

	| klen | vlen | key | val |
	|  2B  |  2B  | ... | ... |
*/

const HEADER = 4

const BTREE_PAGE_SIZE = 4096
const BTREE_MAX_KEY_SIZE = 1000
const BTREE_MAX_VAL_SIZE = 3000

func init() {
	node1max := HEADER + 8 + 2 + 4 + BTREE_MAX_KEY_SIZE + BTREE_MAX_VAL_SIZE
	utils.Assert(node1max <= BTREE_PAGE_SIZE, fmt.Sprintf("node1max exceded BTREE_PAGE_SIZE %d vs %d\n", node1max, BTREE_PAGE_SIZE))
}

type BNode []byte

type BTree struct {
	root uint64

	get func(uint64) []byte
	new func([]byte) uint64
	del func(uint64)
}

const (
	BNODE_NODE = 1
	BNODE_LEAF = 2
)

func (node BNode) btype() uint16 {
	return binary.LittleEndian.Uint16(node[0:2])
}

func (node BNode) nkeys() uint16 {
	return binary.LittleEndian.Uint16(node[2:4])
}

func (node BNode) setHeader(btype uint16, nkeys uint16) {
	binary.LittleEndian.PutUint16(node[0:2], btype)
	binary.LittleEndian.PutUint16(node[2:4], nkeys)
}

func (node BNode) getPtr(idx uint16) uint64 {
	utils.Assert(idx < node.nkeys(), fmt.Sprintf("child pointer position is greater than node num keys %d vs %d\n", idx, node.nkeys()))

	pos := HEADER + 8*idx

	return binary.LittleEndian.Uint64(node[pos:])
}

func (node BNode) setPtr(idx uint16, val uint64) {
	pos := HEADER + 8*idx

	binary.LittleEndian.PutUint64(node[pos:], val)
}

func offsetPos(node BNode, idx uint16) uint16 {
	utils.Assert(1 <= idx && idx <= node.nkeys(), fmt.Sprintf("offset index is out of range idx %d range 1-%d\n", idx, node.nkeys()))

	return HEADER + node.nkeys()*8 + 2*(idx-1)
}

func (node BNode) getOfsset(idx uint16) uint16 {
	if idx == 0 {
		return 0
	}

	return binary.LittleEndian.Uint16(node[offsetPos(node, idx):])
}

func (node BNode) setOfsset(idx uint16, offset uint16) {
	if idx == 0 {
		binary.LittleEndian.PutUint16(node[0:], offset)
		return
	}

	binary.LittleEndian.PutUint16(node[offsetPos(node, idx):], offset)
}

func (node BNode) kvPos(idx uint16) uint16 {
	utils.Assert(idx <= node.nkeys(), fmt.Sprintf("kv index is greater than number of keys %d v %d\n", idx, node.nkeys()))

	return HEADER + 8*node.nkeys() + 2*node.nkeys() + node.getOfsset(idx)
}

func (node BNode) getKey(idx uint16) []byte {
	utils.Assert(idx < node.nkeys(), fmt.Sprintf("key index is greater than or equal to the number of keys %d v %d\n", idx, node.nkeys()))

	pos := node.kvPos(idx)
	keyLen := binary.LittleEndian.Uint16(node[pos:])

	return node[pos+4:][:keyLen]
}

func (node BNode) getVal(idx uint16) []byte {
	utils.Assert(idx < node.nkeys(), fmt.Sprintf("val index is greater than or equal to the number of keys %d v %d\n", idx, node.nkeys()))

	pos := node.kvPos(idx)
	keyLen := binary.LittleEndian.Uint16(node[pos:])
	valLen := binary.LittleEndian.Uint16(node[pos+2:])

	return node[pos+4:][keyLen:valLen]
}

func (node BNode) nbytes() uint16 {
	return node.kvPos(node.nkeys())
}

// TODO: binary search
func nodeLookupLE(node BNode, key []byte) uint16 {
	nkeys := node.nkeys()
	found := uint16(0)
	var cmp int
	for i := uint16(1); i < nkeys; i++ {
		cmp = bytes.Compare(node.getKey(i), key)

		if cmp <= 0 {
			found = i
		}

		if cmp >= 0 {
			break
		}
	}

	return found
}

func nodeAppendKV(new BNode, idx uint16, ptr uint64, key []byte, val []byte) {
	new.setPtr(idx, ptr)

	pos := new.kvPos(idx)
	binary.LittleEndian.PutUint16(new[pos+0:], uint16(len(key)))
	binary.LittleEndian.PutUint16(new[pos+2:], uint16(len(val)))

	copy(new[pos+4:], key)
	copy(new[pos+4+uint16(len(key)):], val)

	new.setOfsset(idx+1, new.getOfsset(idx)+4+uint16(len(key)+len(val)))
}

func nodeAppendRange(new BNode, old BNode, dstNew uint16, srcOld uint16, n uint16) {
	for i := uint16(0); i < n; i++ {
		key := old.getKey(srcOld + i)
		val := old.getVal(srcOld + i)
		ptr := old.getPtr(srcOld + i)

		nodeAppendKV(new, dstNew+i, ptr, key, val)
	}
}

func leafInsert(new BNode, old BNode, idx uint16, key []byte, val []byte) {
	new.setHeader(BNODE_LEAF, old.nkeys()+1)
	nodeAppendRange(new, old, 0, 0, idx)
	nodeAppendKV(new, idx, 0, key, val)
	nodeAppendRange(new, old, idx+1, idx, old.nkeys()-idx)
}

func leafUpdate(new BNode, old BNode, idx uint16, key []byte, val []byte) {
	new.setHeader(BNODE_LEAF, old.nkeys())

	nodeAppendRange(new, old, 0, 0, idx)

	if idx < old.nkeys() && bytes.Equal(old.getKey(idx), key) {
		nodeAppendKV(new, idx, 0, key, val)
	} else {
		new.setHeader(BNODE_LEAF, old.nkeys()+1)
		nodeAppendKV(new, idx, 0, key, val)
		nodeAppendRange(new, old, idx+1, idx, old.nkeys()-idx)
	}
}

func nodeReplaceKidN(tree *BTree, new BNode, old BNode, idx uint16, kids ...BNode) {
	inc := uint16(len(kids))
	new.setHeader(BNODE_NODE, old.nkeys()+inc-1)

	nodeAppendRange(new, old, 0, 0, idx)
	for i, node := range kids {
		nodeAppendKV(new, idx+uint16(i), tree.new(node), node.getKey(0), nil)
	}
	nodeAppendRange(new, old, idx+inc, idx+1, old.nkeys()-(idx+1))
}

func nodeSplit2(left BNode, right BNode, old BNode) {
	var splitIdx uint16 = old.nkeys()
	for i := uint16(1); i <= old.nkeys(); i++ {
		if old.nbytes()-old.kvPos(i) <= BTREE_PAGE_SIZE {
			splitIdx = i
			break
		}
	}

	utils.Assert(splitIdx > 0 && splitIdx < old.nkeys(), fmt.Sprintf("invalid split index for nodeSplit2 %d vs %d\n", splitIdx, old.nkeys()))

	left.setHeader(old.btype(), splitIdx)
	right.setHeader(old.btype(), old.nkeys()-splitIdx)

	nodeAppendRange(left, old, 0, 0, splitIdx)
	nodeAppendRange(right, old, 0, splitIdx, old.nkeys()-splitIdx)
}

func nodeSplit3(old BNode) (uint16, [3]BNode) {
	if old.nbytes() <= BTREE_PAGE_SIZE {
		old = old[:BTREE_PAGE_SIZE]
		return 1, [3]BNode{old}
	}

	left := BNode(make([]byte, 2*BTREE_PAGE_SIZE))
	right := BNode(make([]byte, BTREE_PAGE_SIZE))

	nodeSplit2(left, right, old)
	if left.nbytes() <= BTREE_PAGE_SIZE {
		left = left[:BTREE_PAGE_SIZE]

		return 2, [3]BNode{left, right}
	}

	leftleft := BNode(make([]byte, BTREE_PAGE_SIZE))
	middle := BNode(make([]byte, BTREE_PAGE_SIZE))

	nodeSplit2(leftleft, middle, left)

	utils.Assert(leftleft.nbytes() <= BTREE_PAGE_SIZE, fmt.Sprintf("after second split leftleft num bytes is greater than BTREE_PAGE_SIZE %d vs %d\n", leftleft.nbytes(), BTREE_PAGE_SIZE))
	return 3, [3]BNode{leftleft, middle, right}
}

func nodeInsert(tree *BTree, new BNode, node BNode, idx uint16, key []byte, val []byte) {
	kptr := node.getPtr(idx)
	knode := treeInsert(tree, tree.get(kptr), key, val)
	nsplit, split := nodeSplit3(knode)
	tree.del(kptr)
	nodeReplaceKidN(tree, new, node, idx, split[:nsplit]...)
}

func treeInsert(tree *BTree, node BNode, key []byte, val []byte) BNode {
	new := BNode(make([]byte, 2*BTREE_PAGE_SIZE))
	//new := BNode{data: make([]byte, 2*BTREE_PAGE_SIZE)}

	idx := nodeLookupLE(node, key)

	switch node.btype() {
	case BNODE_LEAF:
		{
			if bytes.Equal(node.getKey(idx), key) {
				leafUpdate(new, node, idx, key, val)
			} else {
				leafInsert(new, node, idx+1, key, val)
			}
		}

	case BNODE_NODE:
		{
			nodeInsert(tree, new, node, idx, key, val)
		}

	default:
		{
			panic(fmt.Sprintf("node type does not match requiremnt %d", node.btype()))
		}
	}

	return new
}

func (tree *BTree) Insert(key []byte, val []byte) error {
	if err := checkLimit(key, val); err != nil {
		return err
	}
	if tree.root == 0 {
		root := BNode(make([]byte, BTREE_PAGE_SIZE))

		root.setHeader(BNODE_LEAF, 2)
		nodeAppendKV(root, 0, 0, nil, nil)
		nodeAppendKV(root, 1, 0, key, val)

		tree.root = tree.new(root)
		return nil
	}

	node := treeInsert(tree, tree.get(tree.root), key, val)

	nsplit, split := nodeSplit3(node)
	tree.del(tree.root)
	if nsplit > 1 {
		root := BNode(make([]byte, BTREE_PAGE_SIZE))
		root.setHeader(BNODE_NODE, nsplit)

		for i, knode := range split[:nsplit] {
			ptr, key := tree.new(knode), knode.getKey(0)

			nodeAppendKV(root, uint16(i), ptr, key, nil)
		}
		tree.root = tree.new(root)
	} else {
		tree.root = tree.new(split[0])
	}

	return nil
}

func (tree *BTree) Delete(key []byte) (bool, error)

// remove a key from a leaf node
func leafDelete(new BNode, old BNode, idx uint16)

// merge 2 nodes into 1
func nodeMerge(new BNode, left BNode, right BNode)

// replace 2 adjacent links with 1
func nodeReplace2Kid(new BNode, old BNode, idx uint16, ptr uint64, key []byte)

func shouldMerge(tree *BTree, node BNode, idx uint16, updated BNode) (int, BNode) {
	if updated.nbytes() > BTREE_PAGE_SIZE/4 {
		return 0, BNode{}
	}

	if idx > 0 {
		sibiling := BNode(tree.get(node.getPtr(idx - 1)))
		merged := sibiling.nbytes() + updated.nbytes() - HEADER

		if merged <= BTREE_PAGE_SIZE {
			return -1, sibiling
		}
	}

	if idx+1 < node.nkeys() {
		sibiling := BNode(tree.get(node.getPtr(idx + 1)))
		merged := sibiling.nbytes() + updated.nbytes() - HEADER

		if merged <= BTREE_PAGE_SIZE {
			return 1, sibiling
		}
	}
	return 0, BNode{}
}

func treeDelete(tree *BTree, node BNode, key []byte) BNode {
	switch node.btype() {
	case BNODE_LEAF:
		{
			leafDelete(node, node, 0)
			return BNode{}
		}
	case BNODE_NODE:
		{
			return nodeDelete(tree, node, 0, []byte{})
		}
	default:
		{
			panic(fmt.Sprintf("node type does not match requiremnt %d", node.btype()))
		}
	}
}

func nodeDelete(tree *BTree, node BNode, idx uint16, key []byte) BNode {
	kptr := node.getPtr(idx)
	updated := treeDelete(tree, tree.get(kptr), key)
	if len(updated) == 0 {
		return BNode{}
	}
	tree.del(kptr)

	new := BNode(make([]byte, BTREE_PAGE_SIZE))
	mergeDir, sibling := shouldMerge(tree, node, idx, updated)
	switch {
	case mergeDir < 0:
		{
			merged := BNode(make([]byte, BTREE_PAGE_SIZE))
			nodeMerge(merged, sibling, updated)
			tree.del(node.getPtr(idx - 1))
			nodeReplace2Kid(new, node, idx-1, tree.new(merged), merged.getKey(0))
		}
	case mergeDir > 0:
		{
			merged := BNode(make([]byte, BTREE_PAGE_SIZE))
			nodeMerge(merged, updated, sibling)
			tree.del(node.getPtr(idx + 1))
			nodeReplace2Kid(new, node, idx, tree.new(merged), merged.getKey(0))
		}
	case mergeDir == 0 && updated.nkeys() == 0:
		{
			utils.Assert(node.nkeys() == 1 && idx == 0, fmt.Sprintf("node should have one key but has %d\n", node.nkeys()))
			new.setHeader(BNODE_NODE, 0)
		}
	case mergeDir == 0 && updated.nkeys() > 0:
		{
			nodeReplaceKidN(tree, new, node, idx, updated)
		}
	}
	return new
}
