// internal/agent/listeners/routes.go
package listeners

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type RouteNode struct {
	NodeGUID  string
	Protocol  string
	NodeType  string
	HopNumber int
	NextHop   *string   // Pointer to handle NULL for final node
	LastSeen  time.Time // From connections table
}

type RoutePath []RouteNode

type RouteManager struct {
	db *sql.DB
}

type SocksRoute struct {
	Path    string
	Handler http.HandlerFunc
	Active  bool
}

type SocksRoutes struct {
	mu     sync.RWMutex
	routes map[string]*SocksRoute
}

func (sr *SocksRoutes) AddRoute(path string, handler http.HandlerFunc) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.routes[path] = &SocksRoute{
		Path:    path,
		Handler: handler,
		Active:  true,
	}
	log.Printf("[SOCKS] Registered new route for path: %s", path)
}

func (sr *SocksRoutes) GetHandler(path string) http.HandlerFunc {
	if sr == nil || sr.routes == nil {
		return nil
	}

	sr.mu.RLock()
	defer sr.mu.RUnlock()

	route, exists := sr.routes[path]
	if !exists || !route.Active || route.Handler == nil {
		return nil
	}
	return route.Handler
}

func NewRouteManager(db *sql.DB) *RouteManager {
	return &RouteManager{db: db}
}

// GetRoutePath finds the complete path from source to target
func (rm *RouteManager) GetRoutePath(sourceGUID, targetGUID string) (RoutePath, error) {
	query := `
        WITH RECURSIVE route_path AS (
            -- Base case: Start with first hop from source
            SELECT 
                lr.source_guid,
                lr.destination_guid,
                lr.next_hop_guid,
                lr.hop_count,
                ARRAY[lr.source_guid] as path,
                1 as depth,
                ARRAY[lr.next_hop_guid] as next_hops
            FROM link_routes lr
            WHERE lr.source_guid = $1
            AND lr.destination_guid = $2
            AND lr.status = 'active'  -- Only look at active routes

            UNION ALL
            
            -- Recursive case
            SELECT 
                r.source_guid,
                r.destination_guid,
                r.next_hop_guid,
                r.hop_count,
                rp.path || r.next_hop_guid,
                rp.depth + 1,
                rp.next_hops || r.next_hop_guid
            FROM link_routes r
            JOIN route_path rp ON r.source_guid = rp.next_hop_guid
            WHERE r.destination_guid = $2
            AND r.status = 'active'  -- Only look at active routes
            AND rp.depth < r.hop_count
        )
        SELECT 
            path_guid as node_guid,
            c.protocol,
            CASE 
                WHEN c.protocol = 'edge' THEN 'entry'
                WHEN c.GUID = $2 THEN 'target'
                ELSE 'hop'
            END as node_type,
            rp.depth as hop_number,
            CASE 
                WHEN path_guid = $2 THEN NULL
                ELSE rp.next_hops[rp.depth]
            END as next_hop,
            c.lastSEEN
        FROM route_path rp
        CROSS JOIN UNNEST(rp.path) WITH ORDINALITY as u(path_guid, ord)
        JOIN connections c ON c.GUID = path_guid
        ORDER BY rp.depth;`

	rows, err := rm.db.Query(query, sourceGUID, targetGUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var path RoutePath
	for rows.Next() {
		var node RouteNode
		err := rows.Scan(
			&node.NodeGUID,
			&node.Protocol,
			&node.NodeType,
			&node.HopNumber,
			&node.NextHop,
			&node.LastSeen,
		)
		if err != nil {
			return nil, err
		}
		path = append(path, node)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	if len(path) == 0 {
		return nil, sql.ErrNoRows
	}

	return path, nil
}

// InsertRoute adds a new route to the link_routes table
func (rm *RouteManager) InsertRoute(sourceGUID, destinationGUID, nextHopGUID string, hopCount int) error {
	query := `
        INSERT INTO link_routes (
            id,
            source_guid,
            destination_guid,
            next_hop_guid,
            hop_count,
            route_created,
            last_used,
            status
        ) VALUES (
            gen_random_uuid(),
            $1,
            $2,
            $3,
            $4,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            'active'
        )
        ON CONFLICT (source_guid, destination_guid) 
        DO UPDATE SET 
            next_hop_guid = EXCLUDED.next_hop_guid,
            hop_count = EXCLUDED.hop_count,
            last_used = CURRENT_TIMESTAMP,
            status = 'active'
    `

	// Validate GUIDs exist in connections table
	validateQuery := `
        SELECT COUNT(*) 
        FROM connections 
        WHERE GUID IN ($1, $2, $3) 
        AND deleted_at IS NULL
    `
	var count int
	err := rm.db.QueryRow(validateQuery, sourceGUID, destinationGUID, nextHopGUID).Scan(&count)
	if err != nil {
		return fmt.Errorf("validation failed: %v", err)
	}
	if count != 3 {
		return fmt.Errorf("one or more GUIDs not found in connections table")
	}

	_, err = rm.db.Exec(query, sourceGUID, destinationGUID, nextHopGUID, hopCount)
	if err != nil {
		return fmt.Errorf("failed to insert route: %v", err)
	}

	return nil
}

// InsertIntermediateNode handles inserting a node between existing nodes
func (rm *RouteManager) InsertIntermediateNode(sourceGUID, intermediateGUID, destinationGUID string) error {
	tx, err := rm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get original hop count
	var originalHopCount int
	err = tx.QueryRow(`
        SELECT hop_count 
        FROM link_routes 
        WHERE source_guid = $1 
        AND destination_guid = $2
    `, sourceGUID, destinationGUID).Scan(&originalHopCount)
	if err != nil {
		return fmt.Errorf("failed to get original route: %v", err)
	}

	// Create two new routes through intermediate node
	err = rm.InsertRoute(sourceGUID, intermediateGUID, intermediateGUID, originalHopCount)
	if err != nil {
		return err
	}

	err = rm.InsertRoute(intermediateGUID, destinationGUID, destinationGUID, originalHopCount)
	if err != nil {
		return err
	}

	// Remove original direct route
	err = rm.RemoveRoute(sourceGUID, destinationGUID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// RemoveRoute performs a soft delete of a specific route
func (rm *RouteManager) RemoveRoute(sourceGUID, destinationGUID string) error {
	query := `
        UPDATE link_routes 
        SET status = 'removed',
            last_used = CURRENT_TIMESTAMP
        WHERE source_guid = $1 
        AND destination_guid = $2
        AND status = 'active'
    `

	result, err := rm.db.Exec(query, sourceGUID, destinationGUID)
	if err != nil {
		return fmt.Errorf("failed to remove route: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rows == 0 {
		return fmt.Errorf("no active route found for source %s to destination %s", sourceGUID, destinationGUID)
	}

	return nil
}

// RemoveAllRoutes performs a soft delete of all routes for a node
func (rm *RouteManager) RemoveAllRoutes(nodeGUID string) error {
	query := `
        UPDATE link_routes 
        SET status = 'removed',
            last_used = CURRENT_TIMESTAMP
        WHERE (source_guid = $1 
            OR destination_guid = $1 
            OR next_hop_guid = $1)
        AND status = 'active'
    `

	result, err := rm.db.Exec(query, nodeGUID)
	if err != nil {
		return fmt.Errorf("failed to remove routes: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rows == 0 {
		return fmt.Errorf("no active routes found for node %s", nodeGUID)
	}

	return nil
}

// PurgeRemovedRoutes physically deletes routes that were removed before the specified duration
func (rm *RouteManager) PurgeRemovedRoutes(olderThan time.Duration) (int64, error) {
	query := `
        DELETE FROM link_routes 
        WHERE status = 'removed' 
        AND last_used < $1
    `

	result, err := rm.db.Exec(query, time.Now().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("failed to purge old routes: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %v", err)
	}

	return rows, nil
}

// Helper methods for RoutePath
func (p RoutePath) IsValid(maxAge time.Duration) bool {
	now := time.Now()
	for _, node := range p {
		if now.Sub(node.LastSeen) > maxAge {
			return false
		}
	}
	return true
}

func (p RoutePath) PathGUIDs() []string {
	guids := make([]string, len(p))
	for i, node := range p {
		guids[i] = node.NodeGUID
	}
	return guids
}

func (p RoutePath) NextHop() (string, error) {
	if len(p) < 2 {
		return "", fmt.Errorf("path too short to determine next hop")
	}
	if p[0].NextHop == nil {
		return "", fmt.Errorf("no next hop available")
	}
	return *p[0].NextHop, nil
}
