package com.baeldung.openapi.model;

import java.net.URI;
import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.openapitools.jackson.nullable.JsonNullable;
import java.time.OffsetDateTime;
import javax.validation.Valid;
import javax.validation.constraints.*;


import java.util.*;

/**
 * CityDto
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.SpringCodegen", date = "2023-02-23T17:27:41.905947700+05:30[Asia/Calcutta]")
public class CityDto   {
  @JsonProperty("city_id")
  private Long cityId;

  @JsonProperty("city_name")
  private String cityName;

  public CityDto cityId(Long cityId) {
    this.cityId = cityId;
    return this;
  }

  /**
   * Get cityId
   * @return cityId
  */
  @ApiModelProperty(required = true, value = "")
  @NotNull


  public Long getCityId() {
    return cityId;
  }

  public void setCityId(Long cityId) {
    this.cityId = cityId;
  }

  public CityDto cityName(String cityName) {
    this.cityName = cityName;
    return this;
  }

  /**
   * Get cityName
   * @return cityName
  */
  @ApiModelProperty(required = true, value = "")
  @NotNull


  public String getCityName() {
    return cityName;
  }

  public void setCityName(String cityName) {
    this.cityName = cityName;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CityDto cityDto = (CityDto) o;
    return Objects.equals(this.cityId, cityDto.cityId) &&
        Objects.equals(this.cityName, cityDto.cityName);
  }

  @Override
  public int hashCode() {
    return Objects.hash(cityId, cityName);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CityDto {\n");
    
    sb.append("    cityId: ").append(toIndentedString(cityId)).append("\n");
    sb.append("    cityName: ").append(toIndentedString(cityName)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}

