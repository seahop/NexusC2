# session_graph.py
# Visual graph showing agent sessions and lateral movement paths

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGraphicsView,
                              QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem,
                              QGraphicsTextItem, QGraphicsRectItem, QPushButton,
                              QLabel, QComboBox, QCheckBox, QMenu, QApplication,
                              QGraphicsItem, QToolTip, QGraphicsDropShadowEffect)
from PyQt6.QtCore import Qt, QPointF, QRectF, QTimer, pyqtSignal, QLineF
from PyQt6.QtGui import (QPen, QBrush, QColor, QPainter, QFont, QPainterPath,
                          QRadialGradient, QLinearGradient, QCursor)
import math
import random


class AgentNode(QGraphicsEllipseItem):
    """Visual node representing an agent in the graph"""

    def __init__(self, agent_data, x, y, radius=30):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.agent_data = agent_data
        self.radius = radius
        self.guid = agent_data.get('guid', '')
        self.is_selected = False
        self.connected_edges = []

        # Position
        self.setPos(x, y)

        # Make interactive
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)

        # Style based on OS
        self.setup_style()

        # Add label
        self.label = QGraphicsTextItem(self)
        self.update_label()

        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(3, 3)

    def setup_style(self):
        """Setup node appearance based on agent properties"""
        os_name = self.agent_data.get('os', '').lower()
        protocol = self.agent_data.get('protocol', '').lower()
        link_type = self.agent_data.get('link_type', '')

        # Determine color based on OS
        if 'windows' in os_name:
            base_color = QColor('#4CAF50')  # Green
        elif 'linux' in os_name:
            base_color = QColor('#FF9800')  # Orange
        elif 'darwin' in os_name or 'mac' in os_name:
            base_color = QColor('#2196F3')  # Blue
        else:
            base_color = QColor('#9E9E9E')  # Gray

        # Create gradient fill
        gradient = QRadialGradient(0, 0, self.radius)
        gradient.setColorAt(0, base_color.lighter(150))
        gradient.setColorAt(0.5, base_color)
        gradient.setColorAt(1, base_color.darker(120))

        self.setBrush(QBrush(gradient))

        # Border style - thicker for linked agents
        if link_type:
            pen = QPen(QColor('#FFFFFF'), 2, Qt.PenStyle.DashLine)
        else:
            pen = QPen(base_color.darker(150), 2)

        self.setPen(pen)

        # Store base color for hover effects
        self.base_color = base_color

    def update_label(self):
        """Update the label text - show useful info without tree-view indentation"""
        # For graph view, build a clean label without indentation prefixes
        # Priority: alias > hostname > short GUID

        # Check if there's a stored alias (not the display_name which has indentation)
        scene = self.scene()
        alias = ''
        guid_len = 12  # Default for graph view (keep it compact)
        if scene and hasattr(scene, 'parent_widget') and scene.parent_widget.agent_tree_widget:
            alias = scene.parent_widget.agent_tree_widget.agent_aliases.get(self.guid, '')
            # Get configured GUID length, but cap at 14 for graph view readability
            configured_len = getattr(scene.parent_widget.agent_tree_widget, 'guid_display_length', 16)
            guid_len = min(configured_len, 14)

        hostname = self.agent_data.get('hostname', '')
        username = self.agent_data.get('username', '')
        link_type = self.agent_data.get('link_type', '')

        # Build multi-line label for more info
        lines = []

        # Line 1: Name (alias or short GUID based on settings)
        if alias:
            name = alias if len(alias) <= 14 else alias[:12] + '..'
        else:
            if guid_len >= 14:
                name = f"{self.guid[:14]}.."
            else:
                name = f"{self.guid[:guid_len]}.."
        lines.append(name)

        # Line 2: Hostname (if available and different from name)
        if hostname and hostname.lower() != 'n/a' and hostname != name:
            host_display = hostname if len(hostname) <= 14 else hostname[:12] + '..'
            lines.append(host_display)

        # Line 3: Username (if available)
        if username and username.lower() != 'n/a':
            user_display = username if len(username) <= 14 else username[:12] + '..'
            lines.append(user_display)

        # Line 4: Link type badge (if linked agent)
        if link_type:
            lines.append(f"[{link_type.upper()}]")

        label_text = '\n'.join(lines)
        self.label.setPlainText(label_text)
        self.label.setDefaultTextColor(QColor('#FFFFFF'))

        font = QFont('Segoe UI', 8, QFont.Weight.Bold)
        self.label.setFont(font)

        # Center label below node
        rect = self.label.boundingRect()
        self.label.setPos(-rect.width() / 2, self.radius + 5)

    def itemChange(self, change, value):
        """Handle item changes - update connected edges when moved"""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.connected_edges:
                edge.update_position()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        """Handle mouse hover - highlight node"""
        self.setScale(1.1)

        # Show tooltip with agent info
        tooltip_text = self._build_tooltip()
        QToolTip.showText(QCursor.pos(), tooltip_text)

        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        """Handle mouse leave - restore normal state"""
        if not self.is_selected:
            self.setScale(1.0)
        QToolTip.hideText()
        super().hoverLeaveEvent(event)

    def _build_tooltip(self):
        """Build tooltip text for the agent"""
        lines = [
            f"<b>{self.agent_data.get('display_name', self.guid[:16])}</b>",
            f"<hr>",
            f"GUID: {self.guid[:24]}...",
            f"Hostname: {self.agent_data.get('hostname', 'N/A')}",
            f"Username: {self.agent_data.get('username', 'N/A')}",
            f"IP: {self.agent_data.get('ip', 'N/A')}",
            f"OS: {self.agent_data.get('os', 'N/A')}",
            f"Protocol: {self.agent_data.get('protocol', 'N/A')}",
        ]

        link_type = self.agent_data.get('link_type', '')
        if link_type:
            lines.append(f"Link: {link_type.upper()}")
            parent = self.agent_data.get('parent_client_id', '')
            if parent:
                lines.append(f"Parent: {parent[:16]}...")

        return '<br>'.join(lines)

    def mousePressEvent(self, event):
        """Handle single click to open agent terminal (matches tree view behavior)"""
        super().mousePressEvent(event)
        # Open terminal on single click
        if event.button() == Qt.MouseButton.LeftButton:
            scene = self.scene()
            if scene and hasattr(scene, 'parent_widget'):
                scene.parent_widget.open_agent_terminal(self.guid)

    def mouseDoubleClickEvent(self, event):
        """Handle double-click to open agent terminal"""
        scene = self.scene()
        if scene and hasattr(scene, 'parent_widget'):
            scene.parent_widget.agent_activated.emit(
                self.agent_data.get('name', ''),
                self.guid
            )
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        """Handle right-click context menu"""
        menu = QMenu()

        open_action = menu.addAction("Open Terminal")
        copy_guid_action = menu.addAction("Copy GUID")
        menu.addSeparator()
        center_action = menu.addAction("Center on Graph")

        action = menu.exec(event.screenPos())

        if action == open_action:
            scene = self.scene()
            if scene and hasattr(scene, 'parent_widget'):
                scene.parent_widget.agent_activated.emit(
                    self.agent_data.get('name', ''),
                    self.guid
                )
        elif action == copy_guid_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.guid)
        elif action == center_action:
            scene = self.scene()
            if scene and hasattr(scene, 'parent_widget'):
                scene.parent_widget.center_on_node(self)


class EdgeLine(QGraphicsLineItem):
    """Visual edge connecting two agent nodes"""

    def __init__(self, source_node, target_node, link_type=''):
        super().__init__()
        self.source_node = source_node
        self.target_node = target_node
        self.link_type = link_type

        # Add to node's edge list
        source_node.connected_edges.append(self)
        target_node.connected_edges.append(self)

        # Style based on link type
        self.setup_style()

        # Initial position
        self.update_position()

        # Arrow head
        self.arrow_head = None
        self.create_arrow_head()

    def setup_style(self):
        """Setup edge appearance based on link type"""
        if self.link_type.lower() == 'smb':
            color = QColor('#FF5722')  # Orange-red for SMB
            style = Qt.PenStyle.DashLine
        elif self.link_type.lower() == 'tcp':
            color = QColor('#2196F3')  # Blue for TCP
            style = Qt.PenStyle.SolidLine
        else:
            color = QColor('#9E9E9E')  # Gray for unknown
            style = Qt.PenStyle.DotLine

        pen = QPen(color, 2, style)
        self.setPen(pen)
        self.edge_color = color

    def create_arrow_head(self):
        """Create arrow head at target end"""
        self.arrow_head = QGraphicsRectItem(self)
        self.arrow_head.setRect(-4, -4, 8, 8)
        self.arrow_head.setBrush(QBrush(self.edge_color))
        self.arrow_head.setPen(QPen(Qt.PenStyle.NoPen))
        self.arrow_head.setRotation(45)

    def update_position(self):
        """Update line position based on node positions"""
        source_pos = self.source_node.scenePos()
        target_pos = self.target_node.scenePos()

        # Calculate line from edge of circles (not centers)
        dx = target_pos.x() - source_pos.x()
        dy = target_pos.y() - source_pos.y()
        length = math.sqrt(dx * dx + dy * dy)

        if length == 0:
            return

        # Normalize
        dx /= length
        dy /= length

        # Offset by radius
        source_offset = self.source_node.radius
        target_offset = self.target_node.radius

        start_x = source_pos.x() + dx * source_offset
        start_y = source_pos.y() + dy * source_offset
        end_x = target_pos.x() - dx * target_offset
        end_y = target_pos.y() - dy * target_offset

        self.setLine(start_x, start_y, end_x, end_y)

        # Update arrow head position
        if self.arrow_head:
            self.arrow_head.setPos(end_x, end_y)
            # Rotate to point at target
            angle = math.degrees(math.atan2(dy, dx))
            self.arrow_head.setRotation(angle + 45)


class SessionGraphWidget(QWidget):
    """Main widget for the session graph visualization"""

    # Signal emitted when an agent is activated (double-clicked)
    agent_activated = pyqtSignal(str, str)  # name, guid

    # Signal emitted when agents are selected
    agents_selected = pyqtSignal(list)  # list of GUIDs

    def __init__(self, terminal_widget=None, agent_tree_widget=None):
        super().__init__()
        self.terminal_widget = terminal_widget
        self.agent_tree_widget = agent_tree_widget

        self.nodes = {}  # guid -> AgentNode
        self.edges = []

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        toolbar = QHBoxLayout()

        # Layout algorithm selector
        toolbar.addWidget(QLabel("Layout:"))
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(['Hierarchical', 'Force-Directed', 'Circular', 'Grid'])
        self.layout_combo.currentTextChanged.connect(self.apply_layout)
        toolbar.addWidget(self.layout_combo)

        toolbar.addSpacing(20)

        # View controls
        zoom_in_btn = QPushButton("+")
        zoom_in_btn.setFixedWidth(30)
        zoom_in_btn.clicked.connect(self.zoom_in)
        toolbar.addWidget(zoom_in_btn)

        zoom_out_btn = QPushButton("-")
        zoom_out_btn.setFixedWidth(30)
        zoom_out_btn.clicked.connect(self.zoom_out)
        toolbar.addWidget(zoom_out_btn)

        fit_btn = QPushButton("Fit")
        fit_btn.clicked.connect(self.fit_in_view)
        toolbar.addWidget(fit_btn)

        toolbar.addSpacing(20)

        # Options
        self.show_labels_check = QCheckBox("Labels")
        self.show_labels_check.setChecked(True)
        self.show_labels_check.toggled.connect(self.toggle_labels)
        toolbar.addWidget(self.show_labels_check)

        self.show_linked_only_check = QCheckBox("Linked Only")
        self.show_linked_only_check.toggled.connect(self.refresh_graph)
        toolbar.addWidget(self.show_linked_only_check)

        toolbar.addStretch()

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_graph)
        toolbar.addWidget(refresh_btn)

        layout.addLayout(toolbar)

        # Graphics view
        self.scene = QGraphicsScene()
        self.scene.parent_widget = self

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.view.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

        # Enable multi-select
        self.view.setRubberBandSelectionMode(Qt.ItemSelectionMode.IntersectsItemShape)

        # Style
        self.view.setStyleSheet("""
            QGraphicsView {
                background-color: #1a1a2e;
                border: none;
            }
        """)

        # Add grid background
        self.scene.setBackgroundBrush(QBrush(QColor('#1a1a2e')))

        layout.addWidget(self.view)

        # Legend
        legend_layout = QHBoxLayout()
        legend_layout.addWidget(self._create_legend_item('#4CAF50', 'Windows'))
        legend_layout.addWidget(self._create_legend_item('#FF9800', 'Linux'))
        legend_layout.addWidget(self._create_legend_item('#2196F3', 'macOS'))
        legend_layout.addWidget(self._create_legend_item('#FF5722', 'SMB Link', is_line=True))
        legend_layout.addWidget(self._create_legend_item('#2196F3', 'TCP Link', is_line=True))
        legend_layout.addStretch()
        layout.addLayout(legend_layout)

        self.setLayout(layout)

        # Connect selection change
        self.scene.selectionChanged.connect(self.on_selection_changed)

    def _create_legend_item(self, color, label, is_line=False):
        """Create a legend item widget"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 0, 10, 0)

        indicator = QLabel()
        if is_line:
            indicator.setFixedSize(20, 3)
        else:
            indicator.setFixedSize(12, 12)
            indicator.setStyleSheet(f"background-color: {color}; border-radius: 6px;")

        if is_line:
            indicator.setStyleSheet(f"background-color: {color};")

        layout.addWidget(indicator)
        layout.addWidget(QLabel(label))

        widget.setLayout(layout)
        return widget

    def refresh_graph(self):
        """Refresh the graph from agent tree data"""
        if not self.agent_tree_widget:
            return

        # Clear existing
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()

        # Get agents to display
        show_linked_only = self.show_linked_only_check.isChecked()

        agents_to_show = []
        for agent in self.agent_tree_widget.agent_data:
            if agent.get('deleted') and not self.agent_tree_widget.show_deleted:
                continue
            if show_linked_only and not agent.get('link_type') and not self._has_linked_children(agent):
                continue
            agents_to_show.append(agent)

        if not agents_to_show:
            # Show placeholder text
            text = self.scene.addText("No agents to display")
            text.setDefaultTextColor(QColor('#666666'))
            return

        # Create nodes
        for agent in agents_to_show:
            node = AgentNode(agent, 0, 0)
            self.scene.addItem(node)
            self.nodes[agent['guid']] = node
            # Update label now that node is in scene (has access to parent_widget for aliases)
            node.update_label()

        # Create edges for linked agents
        for agent in agents_to_show:
            parent_id = agent.get('parent_client_id', '')
            if parent_id and parent_id in self.nodes:
                link_type = agent.get('link_type', '')
                edge = EdgeLine(
                    self.nodes[parent_id],
                    self.nodes[agent['guid']],
                    link_type
                )
                self.scene.addItem(edge)
                self.edges.append(edge)
                # Send edge to back
                edge.setZValue(-1)

        # Apply layout
        self.apply_layout(self.layout_combo.currentText())

    def _has_linked_children(self, agent):
        """Check if an agent has any linked children"""
        guid = agent.get('guid', '')
        for a in self.agent_tree_widget.agent_data:
            if a.get('parent_client_id') == guid:
                return True
        return False

    def apply_layout(self, layout_name):
        """Apply a layout algorithm to position nodes"""
        if not self.nodes:
            return

        if layout_name == 'Hierarchical':
            self._layout_hierarchical()
        elif layout_name == 'Force-Directed':
            self._layout_force_directed()
        elif layout_name == 'Circular':
            self._layout_circular()
        elif layout_name == 'Grid':
            self._layout_grid()

        # Update edges
        for edge in self.edges:
            edge.update_position()

        # Fit view
        QTimer.singleShot(100, self.fit_in_view)

    def _layout_hierarchical(self):
        """Hierarchical layout - parents above children"""
        # Find root nodes (no parent)
        roots = []
        children_map = {}  # parent_guid -> [child_nodes]

        for guid, node in self.nodes.items():
            parent_id = node.agent_data.get('parent_client_id', '')
            if not parent_id or parent_id not in self.nodes:
                roots.append(node)
            else:
                if parent_id not in children_map:
                    children_map[parent_id] = []
                children_map[parent_id].append(node)

        # Layout levels
        level_height = 150
        node_spacing = 120

        def layout_subtree(node, x, y, level=0):
            node.setPos(x, y)

            children = children_map.get(node.guid, [])
            if children:
                total_width = (len(children) - 1) * node_spacing
                start_x = x - total_width / 2
                for i, child in enumerate(children):
                    child_x = start_x + i * node_spacing
                    layout_subtree(child, child_x, y + level_height, level + 1)

        # Layout each root tree
        total_width = (len(roots) - 1) * node_spacing * 2
        start_x = -total_width / 2

        for i, root in enumerate(roots):
            root_x = start_x + i * node_spacing * 2
            layout_subtree(root, root_x, 0)

    def _layout_force_directed(self):
        """Simple force-directed layout"""
        # Initial random positions
        for node in self.nodes.values():
            x = random.uniform(-300, 300)
            y = random.uniform(-300, 300)
            node.setPos(x, y)

        # Iterate force simulation
        iterations = 50
        repulsion = 5000
        attraction = 0.01
        damping = 0.9

        for _ in range(iterations):
            forces = {guid: QPointF(0, 0) for guid in self.nodes}

            # Repulsion between all nodes
            nodes_list = list(self.nodes.values())
            for i, node1 in enumerate(nodes_list):
                for node2 in nodes_list[i + 1:]:
                    dx = node1.x() - node2.x()
                    dy = node1.y() - node2.y()
                    dist = max(math.sqrt(dx * dx + dy * dy), 1)

                    force = repulsion / (dist * dist)
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force

                    forces[node1.guid] += QPointF(fx, fy)
                    forces[node2.guid] -= QPointF(fx, fy)

            # Attraction along edges
            for edge in self.edges:
                source = edge.source_node
                target = edge.target_node

                dx = target.x() - source.x()
                dy = target.y() - source.y()
                dist = math.sqrt(dx * dx + dy * dy)

                force = dist * attraction
                fx = dx * force
                fy = dy * force

                forces[source.guid] += QPointF(fx, fy)
                forces[target.guid] -= QPointF(fx, fy)

            # Apply forces
            for guid, node in self.nodes.items():
                force = forces[guid]
                new_x = node.x() + force.x() * damping
                new_y = node.y() + force.y() * damping
                node.setPos(new_x, new_y)

    def _layout_circular(self):
        """Circular layout"""
        count = len(self.nodes)
        if count == 0:
            return

        radius = max(100, count * 30)
        angle_step = 2 * math.pi / count

        for i, node in enumerate(self.nodes.values()):
            angle = i * angle_step - math.pi / 2  # Start from top
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            node.setPos(x, y)

    def _layout_grid(self):
        """Grid layout"""
        count = len(self.nodes)
        if count == 0:
            return

        cols = max(1, int(math.ceil(math.sqrt(count))))
        spacing = 120

        for i, node in enumerate(self.nodes.values()):
            row = i // cols
            col = i % cols
            x = col * spacing - (cols - 1) * spacing / 2
            y = row * spacing
            node.setPos(x, y)

    def zoom_in(self):
        """Zoom in the view"""
        self.view.scale(1.2, 1.2)

    def zoom_out(self):
        """Zoom out the view"""
        self.view.scale(0.8, 0.8)

    def fit_in_view(self):
        """Fit all nodes in view"""
        rect = self.scene.itemsBoundingRect()
        rect.adjust(-50, -50, 50, 50)
        self.view.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)

    def center_on_node(self, node):
        """Center the view on a specific node"""
        self.view.centerOn(node)

    def toggle_labels(self, show):
        """Toggle label visibility"""
        for node in self.nodes.values():
            node.label.setVisible(show)

    def on_selection_changed(self):
        """Handle selection change in the graph"""
        selected_guids = []
        for item in self.scene.selectedItems():
            if isinstance(item, AgentNode):
                selected_guids.append(item.guid)

        self.agents_selected.emit(selected_guids)

    def get_selected_agent_guids(self):
        """Get list of selected agent GUIDs"""
        guids = []
        for item in self.scene.selectedItems():
            if isinstance(item, AgentNode):
                guids.append(item.guid)
        return guids

    def select_agents(self, guids):
        """Select agents by GUID list"""
        self.scene.clearSelection()
        for guid in guids:
            if guid in self.nodes:
                self.nodes[guid].setSelected(True)

    def open_agent_terminal(self, guid):
        """Open terminal for an agent (called from node click)"""
        if not self.agent_tree_widget or not self.terminal_widget:
            return

        agent = self.agent_tree_widget.agent_by_guid.get(guid)
        if agent:
            self.agent_activated.emit(agent['name'], guid)
            self.terminal_widget.add_agent_tab(agent['name'], guid)

    def highlight_path(self, from_guid, to_guid):
        """Highlight the path between two agents"""
        # Find path using BFS
        if from_guid not in self.nodes or to_guid not in self.nodes:
            return

        # Build adjacency map
        adjacency = {}
        for edge in self.edges:
            source_guid = edge.source_node.guid
            target_guid = edge.target_node.guid

            if source_guid not in adjacency:
                adjacency[source_guid] = []
            if target_guid not in adjacency:
                adjacency[target_guid] = []

            adjacency[source_guid].append((target_guid, edge))
            adjacency[target_guid].append((source_guid, edge))

        # BFS to find path
        visited = {from_guid}
        queue = [(from_guid, [])]

        while queue:
            current, path = queue.pop(0)

            if current == to_guid:
                # Highlight path
                for edge in path:
                    edge.setPen(QPen(QColor('#FFEB3B'), 4))
                return

            for neighbor, edge in adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [edge]))
