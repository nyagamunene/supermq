// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type PermissionConfig struct {
	Entities map[string]EntityPermissions `yaml:",inline"`
}

type EntityPermissions struct {
	Operations      []map[string]interface{} `yaml:"operations"`
	RolesOperations []map[string]interface{} `yaml:"roles_operations"`
}

func ParsePermissionsFile(filePath string) (*PermissionConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read permissions file: %w", err)
	}

	var config PermissionConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse permissions file: %w", err)
	}

	return &config, nil
}

func (pc *PermissionConfig) GetEntityPermissions(entityType string) (map[string]Permission, map[string]Permission, error) {
	entityPerms, ok := pc.Entities[entityType]
	if !ok {
		return nil, nil, fmt.Errorf("entity type %s not found in permissions file", entityType)
	}

	operations := make(map[string]Permission)
	for _, op := range entityPerms.Operations {
		for name, value := range op {
			perm := extractPermission(value)
			if perm != "" {
				operations[name] = Permission(perm)
			}
		}
	}

	rolesOperations := make(map[string]Permission)
	for _, op := range entityPerms.RolesOperations {
		for name, value := range op {
			perm := extractPermission(value)
			if perm != "" {
				rolesOperations[name] = Permission(perm)
			}
		}
	}

	return operations, rolesOperations, nil
}

func (pc *PermissionConfig) GetAuthOperations(entityType string) (map[string]string, map[string]string, error) {
	entityPerms, ok := pc.Entities[entityType]
	if !ok {
		return nil, nil, fmt.Errorf("entity type %s not found in permissions file", entityType)
	}

	operations := make(map[string]string)
	for _, op := range entityPerms.Operations {
		for name, value := range op {
			authOp := extractAuthOperation(value)
			if authOp != "" {
				operations[name] = authOp
			}
		}
	}

	rolesOperations := make(map[string]string)
	for _, op := range entityPerms.RolesOperations {
		for name, value := range op {
			authOp := extractAuthOperation(value)
			if authOp != "" {
				rolesOperations[name] = authOp
			}
		}
	}

	return operations, rolesOperations, nil
}

func extractPermission(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]interface{}:
		if perm, ok := v["permission"].(string); ok {
			return perm
		}
	}
	return ""
}

func extractAuthOperation(value interface{}) string {
	if m, ok := value.(map[string]interface{}); ok {
		if authOp, ok := m["auth_operation"].(string); ok {
			return authOp
		}
	}
	return ""
}
