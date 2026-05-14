/** Entity-relationship graph with Map-based backing. */

export interface Entity {
  id: string;
  type: string;
  properties: Record<string, unknown>;
  createdAt: number;
}

export interface Relation {
  from: string;
  to: string;
  type: string;
  properties: Record<string, unknown>;
  createdAt: number;
}

export class KnowledgeGraph {
  private entities = new Map<string, Entity>();
  private relations = new Map<string, Relation[]>();

  addEntity(entity: Entity): void {
    this.entities.set(entity.id, entity);
  }

  removeEntity(id: string): void {
    this.entities.delete(id);
    this.relations.delete(id);
    for (const [sourceId, rels] of this.relations) {
      const filtered = rels.filter((r) => r.to !== id);
      if (filtered.length === 0) {
        this.relations.delete(sourceId);
      } else {
        this.relations.set(sourceId, filtered);
      }
    }
  }

  getEntity(id: string): Entity | undefined {
    return this.entities.get(id);
  }

  addRelation(relation: Relation): void {
    const existing = this.relations.get(relation.from) ?? [];
    existing.push(relation);
    this.relations.set(relation.from, existing);
  }

  getRelations(entityId: string): Relation[] {
    return this.relations.get(entityId) ?? [];
  }

  query(type: string, properties?: Record<string, unknown>): Entity[] {
    const results: Entity[] = [];
    for (const entity of this.entities.values()) {
      if (entity.type !== type) continue;
      if (properties) {
        let match = true;
        for (const [key, val] of Object.entries(properties)) {
          if (entity.properties[key] !== val) {
            match = false;
            break;
          }
        }
        if (!match) continue;
      }
      results.push(entity);
    }
    return results;
  }

  getState(): {
    entities: Record<string, Entity>;
    relations: Record<string, Relation[]>;
  } {
    const entities: Record<string, Entity> = {};
    for (const [id, entity] of this.entities) {
      entities[id] = entity;
    }
    const relations: Record<string, Relation[]> = {};
    for (const [id, rels] of this.relations) {
      relations[id] = rels;
    }
    return { entities, relations };
  }

  clear(): void {
    this.entities.clear();
    this.relations.clear();
  }
}
