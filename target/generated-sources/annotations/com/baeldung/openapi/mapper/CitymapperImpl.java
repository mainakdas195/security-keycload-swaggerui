package com.baeldung.openapi.mapper;

import com.baeldung.openapi.entity.City;
import com.baeldung.openapi.model.CityDto;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Generated;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2023-02-23T18:22:33+0530",
    comments = "version: 1.5.3.Final, compiler: Eclipse JDT (IDE) 3.21.0.v20200304-1404, environment: Java 1.8.0_333 (Oracle Corporation)"
)
public class CitymapperImpl implements Citymapper {

    @Override
    public CityDto cityToCityDTO(City city) {
        if ( city == null ) {
            return null;
        }

        CityDto cityDto = new CityDto();

        if ( city.getId() != null ) {
            cityDto.setCityId( city.getId().longValue() );
        }
        cityDto.setCityName( city.getName() );

        return cityDto;
    }

    @Override
    public List<CityDto> convertCityListToCityDTOList(List<City> list) {
        if ( list == null ) {
            return null;
        }

        List<CityDto> list1 = new ArrayList<CityDto>( list.size() );
        for ( City city : list ) {
            list1.add( cityToCityDTO( city ) );
        }

        return list1;
    }
}
