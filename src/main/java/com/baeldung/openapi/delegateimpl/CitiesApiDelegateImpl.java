package com.baeldung.openapi.delegateimpl;

import java.util.List;

import org.mapstruct.factory.Mappers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException.BadRequest;

import com.baeldung.openapi.api.CitiesApi;
//import com.baeldung.openapi.api.CitiesApiDelegate;
import com.baeldung.openapi.entity.City;
import com.baeldung.openapi.exception.BadRequestException;
import com.baeldung.openapi.exception.ExceptionConstant;
import com.baeldung.openapi.mapper.Citymapper;
import com.baeldung.openapi.model.CityDto;
import com.baeldung.openapi.service.CityService;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@SecurityRequirement(name = "Bearer Authentication")
public class CitiesApiDelegateImpl implements CitiesApi {
	
	@Autowired
	CityService cityService;
	
	Citymapper mapper = Mappers.getMapper(Citymapper.class);

	@Override
	public ResponseEntity<List<CityDto>> getAllCities() {
		// TODO Auto-generated method stub
		
			List<City> all = cityService.getAll();
//			if(all.size()>0) {
//				throw new BadRequestException(ExceptionConstant.NO_CITIES_FOUND_ERROR_CODE_001, ExceptionConstant.NO_CITIES_FOUND);
//			}
			
			for(City city : all) {
				CityDto cityToCityDTO = mapper.cityToCityDTO(city);
				System.out.print(cityToCityDTO);
			}
			
			List<CityDto> cityDtoList = mapper.convertCityListToCityDTOList(all);
			System.out.print(cityDtoList);
			
		
		return new ResponseEntity(cityDtoList, HttpStatus.OK);
	}

}
