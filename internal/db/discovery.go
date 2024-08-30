package db

import (
	"CZERTAINLY-CT-Logs-Discovery-Provider/internal/model"
	"context"
	"encoding/json"
	"fmt"
	"gorm.io/datatypes"
	"math"

	"gorm.io/gorm"
)

type Discovery struct {
	Id           uint `gorm:"primarykey"`
	UUID         string
	Name         string
	Status       model.DiscoveryStatus
	Meta         datatypes.JSON `gorm:"type:json"`
	Certificates []Certificate  `gorm:"many2many:discovery_certificates;"`
}

type Certificate struct {
	Id            uint `gorm:"primarykey"`
	UUID          string
	Base64Content string
	Meta          datatypes.JSON `gorm:"type:json"`
	Discoveries   []Discovery    `gorm:"many2many:discovery_certificates;"`
}

// Marshal your MetadataAttribute array to JSON for storing in the Meta field
func (d *Discovery) SetMeta(attributes []model.MetadataAttribute) error {
	jsonData, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	d.Meta = jsonData
	return nil
}

// Unmarshal your JSON data from the Meta field into a MetadataAttribute array
func (d *Discovery) GetMeta() ([]model.MetadataAttribute, error) {
	attributes := model.UnmarshalAttributes(context.TODO(), d.Meta)
	if attributes == nil {
		return nil, fmt.Errorf("failed to unmarshal metadata attributes")
	} else {
		var metaAttributes []model.MetadataAttribute
		for _, attribute := range attributes {
			metadataAttribute := attribute.(model.MetadataAttribute)
			metaAttributes = append(metaAttributes, metadataAttribute)
		}
		return metaAttributes, nil
	}
}

// Marshal your MetadataAttribute array to JSON for storing in the Meta field
func (d *Certificate) SetMeta(attributes []model.MetadataAttribute) error {
	jsonData, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	d.Meta = jsonData
	return nil
}

// Unmarshal your JSON data from the Meta field into a MetadataAttribute array
func (d *Certificate) GetMeta() ([]model.MetadataAttribute, error) {
	attributes := model.UnmarshalAttributes(context.TODO(), d.Meta)
	if attributes == nil {
		return nil, fmt.Errorf("failed to unmarshal metadata attributes")
	} else {
		var metaAttributes []model.MetadataAttribute
		for _, attribute := range attributes {
			metadataAttribute := attribute.(model.MetadataAttribute)
			metaAttributes = append(metaAttributes, metadataAttribute)
		}
		return metaAttributes, nil
	}
}

type DiscoveryRepository struct {
	db *gorm.DB
}

func NewDiscoveryRepository(db *gorm.DB) (*DiscoveryRepository, error) {
	return &DiscoveryRepository{db: db}, nil
}

func (d *DiscoveryRepository) CreateDiscovery(discovery *Discovery) error {
	var exisitngDiscovery Discovery
	d.db.First(&exisitngDiscovery, "name = ?", discovery.Name)
	if exisitngDiscovery.Name != "" {
		return fmt.Errorf("discovery instance with name %s already exists", discovery.Name)
	}

	result := d.db.Create(&discovery)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (d *DiscoveryRepository) AssociateCertificatesToDiscovery(discovery *Discovery, certificates ...*Certificate) error {
	for _, certificate := range certificates {
		d.db.FirstOrCreate(&certificate, Certificate{UUID: certificate.UUID})
	}
	assoc := d.db.Model(&discovery).Association("Certificates")
	err := assoc.Append(&certificates)
	if err != nil {
		return err
	}
	return nil
}

func (d *DiscoveryRepository) CreateDiscoveryAndAssociateCertificates(discovery *Discovery, certificates ...*Certificate) error {
	d.db.Create(&discovery)
	for _, certificate := range certificates {
		d.db.FirstOrCreate(&certificate, Certificate{UUID: certificate.UUID})
		assoc := d.db.Model(&discovery).Association("Certificates")
		err := assoc.Append(&certificate)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *DiscoveryRepository) FindDiscoveryByUUID(uuid string) (*Discovery, error) {
	var discovery Discovery
	if err := d.db.Preload("Certificates").First(&discovery, "uuid = ?", uuid).Error; err != nil {
		return nil, err
	}
	return &discovery, nil
}

func (d *DiscoveryRepository) UpdateDiscovery(discovery *Discovery) error {
	result := d.db.Save(&discovery)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (d *DiscoveryRepository) List(pagination Pagination, discovery *Discovery) (*Pagination, error) {
	var certificates []*Certificate
	page := pagination.Page
	pageSize := pagination.Limit
	var count int
	offset := (page - 1) * pageSize
	d.db.Table("certificates").Select("certificates.*").
		Joins("JOIN discovery_certificates ON discovery_certificates.certificate_id = certificates.id").
		Where("discovery_certificates.discovery_id = ?", discovery.Id).
		Order("id asc").
		Offset(offset).Limit(pageSize).Find(&certificates)

	pagination.Rows = certificates
	pagination.TotalRows = int64(len(discovery.Certificates))
	totalPages := int(math.Ceil(float64(count) / float64(pagination.Limit)))
	pagination.TotalPages = totalPages
	return &pagination, nil
}

func (d *DiscoveryRepository) DeleteDiscovery(discovery *Discovery) error {
	result := d.db.Delete(&discovery)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

type Pagination struct {
	Limit      int         `json:"limit,omitempty"`
	Page       int         `json:"page,omitempty"`
	Sort       string      `json:"sort,omitempty"`
	TotalRows  int64       `json:"total_rows"`
	TotalPages int         `json:"total_pages"`
	Rows       interface{} `json:"rows"`
}

func (p *Pagination) GetOffset() int {
	return (p.GetPage() - 1) * p.GetLimit()
}

func (p *Pagination) GetLimit() int {
	if p.Limit == 0 {
		p.Limit = 10
	}
	return p.Limit
}

func (p *Pagination) GetPage() int {
	if p.Page == 0 {
		p.Page = 1
	}
	return p.Page
}
