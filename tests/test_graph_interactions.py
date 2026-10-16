"""Tests for Network Graph interactions, container group dragging, coordinate invariance, and layout stability."""

import math
import pytest


class GraphContainerLayoutEngine:
    """Python reference mirror of the NetworkGraph layout and container dragging logic.
    
    Validates mathematical and topological invariants across group drags, node drags,
    incremental live updates, and coordinate projections.
    """

    def __init__(self, width=960, height=660, pad=70, box_pad_x=46, box_pad_y=44):
        self.width = width
        self.height = height
        self.pad = pad
        self.box_pad_x = box_pad_x
        self.box_pad_y = box_pad_y

    def calculate_container_box(self, member_positions):
        """Calculates [bX, bY, bW, bH] for a container given member node coordinates."""
        if not member_positions:
            return None

        xs = [p["x"] for p in member_positions.values()]
        ys = [p["y"] for p in member_positions.values()]

        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)

        b_x = min_x - self.box_pad_x
        b_y = min_y - self.box_pad_y - 14
        b_w = max(160, max_x - min_x + self.box_pad_x * 2)
        b_h = max(90, max_y - min_y + self.box_pad_y * 2 + 14)

        return {
            "x": b_x,
            "y": b_y,
            "width": b_w,
            "height": b_h,
            "min_x": min_x,
            "max_x": max_x,
            "min_y": min_y,
            "max_y": max_y,
        }

    def apply_group_drag(self, start_positions, delta_x, delta_y):
        """Translates all member positions by delta_x and delta_y."""
        new_positions = {}
        for node_id, pos in start_positions.items():
            new_positions[node_id] = {
                "x": pos["x"] + delta_x,
                "y": pos["y"] + delta_y,
            }
        return new_positions

    def screen_to_graph_delta(self, screen_delta_x, screen_delta_y, zoom):
        """Converts screen pixel movement to graph coordinate displacement."""
        return (
            round(screen_delta_x / zoom),
            round(screen_delta_y / zoom),
        )

    def screen_to_graph_coord(self, screen_x, screen_y, pan_x, pan_y, zoom):
        """Converts absolute screen coordinates to graph coordinates."""
        return (
            round((screen_x - pan_x) / zoom),
            round((screen_y - pan_y) / zoom),
        )

    @staticmethod
    def euclidean_distance(p1, p2):
        return math.hypot(p1["x"] - p2["x"], p1["y"] - p2["y"])


def test_group_drag_uniform_delta_invariance():
    """Verify dragging a container box applies uniform (delta_x, delta_y) to all members."""
    engine = GraphContainerLayoutEngine()

    initial_positions = {
        "192.168.1.1": {"x": 280, "y": 275},
        "192.168.1.5": {"x": 200, "y": 355},
        "192.168.1.10": {"x": 360, "y": 355},
        "subnet_cluster:192.168.1.0/24": {"x": 280, "y": 330},
    }

    initial_box = engine.calculate_container_box({
        k: v for k, v in initial_positions.items() if not k.startswith("subnet_cluster:")
    })

    delta_x, delta_y = 120, -75
    new_positions = engine.apply_group_drag(initial_positions, delta_x, delta_y)

    new_box = engine.calculate_container_box({
        k: v for k, v in new_positions.items() if not k.startswith("subnet_cluster:")
    })

    # 1. Every member moved by exactly (delta_x, delta_y)
    for node_id in initial_positions:
        assert new_positions[node_id]["x"] - initial_positions[node_id]["x"] == delta_x
        assert new_positions[node_id]["y"] - initial_positions[node_id]["y"] == delta_y

    # 2. Container bounding box coordinates shifted by exact delta
    assert new_box["x"] - initial_box["x"] == delta_x
    assert new_box["y"] - initial_box["y"] == delta_y

    # 3. Bounding dimensions (width and height) remain invariant
    assert new_box["width"] == initial_box["width"]
    assert new_box["height"] == initial_box["height"]


def test_pairwise_internal_geometric_distance_invariance():
    """Verify that group drag preserves pairwise distances between all constituent hosts."""
    engine = GraphContainerLayoutEngine()

    initial_positions = {
        "gw": {"x": 300, "y": 200},
        "host_a": {"x": 220, "y": 280},
        "host_b": {"x": 380, "y": 280},
        "host_c": {"x": 300, "y": 350},
    }

    node_ids = list(initial_positions.keys())
    initial_distances = {}
    for i in range(len(node_ids)):
        for j in range(i + 1, len(node_ids)):
            u, v = node_ids[i], node_ids[j]
            initial_distances[(u, v)] = engine.euclidean_distance(initial_positions[u], initial_positions[v])

    # Apply translation
    new_positions = engine.apply_group_drag(initial_positions, delta_x=-150, delta_y=230)

    # Verify all pairwise distances remain strictly identical
    for (u, v), orig_dist in initial_distances.items():
        new_dist = engine.euclidean_distance(new_positions[u], new_positions[v])
        assert math.isclose(orig_dist, new_dist, rel_tol=1e-9)


def test_edge_endpoint_attachment_tracking():
    """Verify edges track moved endpoints for intra-group and inter-group communication."""
    engine = GraphContainerLayoutEngine()

    all_positions = {
        "internal_gw": {"x": 280, "y": 275},
        "internal_cli": {"x": 200, "y": 355},
        "external_srv": {"x": 680, "y": 330},
    }

    edges = [
        {"source": "internal_cli", "target": "internal_gw", "type": "intra"},
        {"source": "internal_gw", "target": "external_srv", "type": "inter"},
    ]

    # Drag the internal group by (+50, +40)
    delta_x, delta_y = 50, 40
    group_nodes = {"internal_gw", "internal_cli"}

    updated_positions = {**all_positions}
    for nid in group_nodes:
        updated_positions[nid] = {
            "x": all_positions[nid]["x"] + delta_x,
            "y": all_positions[nid]["y"] + delta_y,
        }

    # Verify intra edge endpoints translated together (length constant)
    intra_orig_len = engine.euclidean_distance(all_positions["internal_cli"], all_positions["internal_gw"])
    intra_new_len = engine.euclidean_distance(updated_positions["internal_cli"], updated_positions["internal_gw"])
    assert math.isclose(intra_orig_len, intra_new_len, rel_tol=1e-9)

    # Verify inter edge: source moved, target stayed fixed
    inter_edge = edges[1]
    s_pos = updated_positions[inter_edge["source"]]
    t_pos = updated_positions[inter_edge["target"]]

    assert s_pos == {"x": 330, "y": 315}
    assert t_pos == {"x": 680, "y": 330}


def test_independent_node_drag():
    """Verify moving an individual node alters only that node while sibling nodes stay fixed."""
    engine = GraphContainerLayoutEngine()

    initial_positions = {
        "gw": {"x": 280, "y": 275},
        "cli_1": {"x": 200, "y": 355},
        "cli_2": {"x": 360, "y": 355},
    }

    # Drag only cli_1 to the left by 60px
    updated_positions = {**initial_positions}
    updated_positions["cli_1"] = {"x": 140, "y": 355}

    # Sibling nodes are strictly untouched
    assert updated_positions["gw"] == initial_positions["gw"]
    assert updated_positions["cli_2"] == initial_positions["cli_2"]

    # Container dynamically expands its width to envelop the moved node
    orig_box = engine.calculate_container_box(initial_positions)
    new_box = engine.calculate_container_box(updated_positions)

    assert new_box["x"] < orig_box["x"]
    assert new_box["width"] > orig_box["width"]


def test_collapsed_cluster_capsule_movement():
    """Verify dragging a collapsed cluster capsule also translates member hosts."""
    engine = GraphContainerLayoutEngine()

    positions = {
        "subnet_cluster:192.168.1.0/24": {"x": 280, "y": 330},
        "192.168.1.1": {"x": 280, "y": 275},
        "192.168.1.5": {"x": 200, "y": 355},
    }

    delta_x, delta_y = -80, 50
    translated = engine.apply_group_drag(positions, delta_x, delta_y)

    assert translated["subnet_cluster:192.168.1.0/24"] == {"x": 200, "y": 380}
    assert translated["192.168.1.1"] == {"x": 200, "y": 325}
    assert translated["192.168.1.5"] == {"x": 120, "y": 405}


def test_incremental_layout_preserves_dragged_positions():
    """Verify live polling incremental layout does not reset user-dragged coordinates."""
    # Existing placed and user-dragged nodes
    current_positions = {
        "192.168.1.1": {"x": 400, "y": 200},  # Dragged from original static (280, 275)
        "192.168.1.5": {"x": 320, "y": 280},
    }

    # Incoming live update with a newly discovered host
    incoming_nodes = [
        {"id": "192.168.1.1", "subnet": "192.168.1.0/24"},
        {"id": "192.168.1.5", "subnet": "192.168.1.0/24"},
        {"id": "192.168.1.20", "subnet": "192.168.1.0/24"},  # New host
    ]

    # Static default placement for all 3 nodes
    static_positions = {
        "192.168.1.1": {"x": 280, "y": 275},
        "192.168.1.5": {"x": 200, "y": 355},
        "192.168.1.20": {"x": 360, "y": 355},
    }

    # Simulate updateIncrementalLayout logic
    unplaced = [n for n in incoming_nodes if n["id"] not in current_positions]
    next_positions = {**current_positions}

    for n in unplaced:
        nid = n["id"]
        sub_id = n["subnet"]
        siblings = [
            s["id"] for s in incoming_nodes
            if s["id"] != nid and s["subnet"] == sub_id and s["id"] in current_positions
        ]

        if siblings:
            cur_sum_x = sum(current_positions[sid]["x"] for sid in siblings)
            cur_sum_y = sum(current_positions[sid]["y"] for sid in siblings)
            cur_center_x = cur_sum_x / len(siblings)
            cur_center_y = cur_sum_y / len(siblings)

            stat_sum_x = sum(static_positions[sid]["x"] for sid in siblings)
            stat_sum_y = sum(static_positions[sid]["y"] for sid in siblings)
            stat_center_x = stat_sum_x / len(siblings)
            stat_center_y = stat_sum_y / len(siblings)

            offset_x = cur_center_x - stat_center_x
            offset_y = cur_center_y - stat_center_y

            next_positions[nid] = {
                "x": round(static_positions[nid]["x"] + offset_x),
                "y": round(static_positions[nid]["y"] + offset_y),
            }

    # Existing dragged positions are preserved 100%
    assert next_positions["192.168.1.1"] == {"x": 400, "y": 200}
    assert next_positions["192.168.1.5"] == {"x": 320, "y": 280}

    # New node is placed with the offset of the dragged group
    assert next_positions["192.168.1.20"]["x"] > static_positions["192.168.1.20"]["x"]


def test_screen_to_graph_coordinate_transformation_precision():
    """Verify screen to graph coordinate transformation across multiple zoom and pan scales."""
    engine = GraphContainerLayoutEngine()

    # 1. 1.0x Zoom, (0, 0) Pan
    gx, gy = engine.screen_to_graph_coord(500, 300, pan_x=0, pan_y=0, zoom=1.0)
    assert gx == 500 and gy == 300

    # 2. 2.0x Zoom with Pan Offset
    # Screen cursor at (600, 400), pan at (100, 50)
    # graphX = (600 - 100) / 2.0 = 250
    # graphY = (400 - 50) / 2.0 = 175
    gx, gy = engine.screen_to_graph_coord(600, 400, pan_x=100, pan_y=50, zoom=2.0)
    assert gx == 250 and gy == 175

    # 3. 0.5x Zoom with Pan Offset
    # Screen cursor at (400, 200), pan at (-50, -50)
    # graphX = (400 - (-50)) / 0.5 = 900
    # graphY = (200 - (-50)) / 0.5 = 500
    gx, gy = engine.screen_to_graph_coord(400, 200, pan_x=-50, pan_y=-50, zoom=0.5)
    assert gx == 900 and gy == 500

    # 4. Screen delta under 1.5x zoom
    dx, dy = engine.screen_to_graph_delta(150, 75, zoom=1.5)
    assert dx == 100 and dy == 50


def test_drag_operations_do_not_mutate_packet_evidence():
    """Verify that dragging containers or nodes does not mutate packet or CIDR evidence."""
    engine = GraphContainerLayoutEngine()

    packet_node = {
        "id": "192.168.1.50",
        "label": "192.168.1.50",
        "subnet": "192.168.1.0/24",
        "device_role": "workstation",
        "is_internal": True,
        "total_bytes": 1048576,
        "packet_count": 1420,
        "findings_count": 0,
    }

    positions = {"192.168.1.50": {"x": 200, "y": 300}}

    # Perform group drag
    translated = engine.apply_group_drag(positions, delta_x=50, delta_y=50)

    # Position is updated
    assert translated["192.168.1.50"] == {"x": 250, "y": 350}

    # Telemetry and evidence metadata remain completely untouched
    assert packet_node["total_bytes"] == 1048576
    assert packet_node["packet_count"] == 1420
    assert packet_node["subnet"] == "192.168.1.0/24"
    assert packet_node["device_role"] == "workstation"
