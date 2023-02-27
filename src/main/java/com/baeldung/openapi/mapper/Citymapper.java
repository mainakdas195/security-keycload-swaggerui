package com.baeldung.openapi.mapper;

import java.util.List;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.baeldung.openapi.entity.City;
import com.baeldung.openapi.model.CityDto;

@Mapper
public interface Citymapper {
	
	@Mapping(target="cityId", source="city.id")
    @Mapping(target="cityName", source="city.name")
    CityDto cityToCityDTO(City city);
	
	List<CityDto> convertCityListToCityDTOList(List<City> list);

}
