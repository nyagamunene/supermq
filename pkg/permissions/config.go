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

type OperationInfo struct {
	Permission Permission
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

func (pc *PermissionConfig) GetEntityPermissions(entityType string) (map[string]OperationInfo, map[string]OperationInfo, error) {
	entityPerms, ok := pc.Entities[entityType]
	if !ok {
		return nil, nil, fmt.Errorf("entity type %s not found in permissions file", entityType)
	}

	operations := make(map[string]OperationInfo)
	for _, op := range entityPerms.Operations {
		for name, value := range op {
			perm := extractPermission(value)
			if perm != "" {
				operations[name] = OperationInfo{
					Permission: Permission(perm),
				}
			}
		}
	}

	rolesOperations := make(map[string]OperationInfo)
	for _, op := range entityPerms.RolesOperations {
		for name, value := range op {
			perm := extractPermission(value)
			if perm != "" {
				rolesOperations[name] = OperationInfo{
					Permission: Permission(perm),
				}
			}
		}
	}

	return operations, rolesOperations, nil
}

func extractPermission(value interface{}) string {
	if v, ok := value.(string); ok {
		return v
	}
	return ""
}
