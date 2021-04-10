import { CarsRepositoryInMemory } from "@modules/cars/repositories/in-memory/CarsRepositoryInMemory";

import { ListAvailableCarsUseCase } from "./ListAvailableCarsUseCase";

let listAvailableCarsUseCase: ListAvailableCarsUseCase;
let carsRepositoryInMemory: CarsRepositoryInMemory;

describe("List Cars", () => {
  beforeEach(() => {
    carsRepositoryInMemory = new CarsRepositoryInMemory();
    listAvailableCarsUseCase = new ListAvailableCarsUseCase(
      carsRepositoryInMemory
    );
  });

  it("should be able to list all available cars", async () => {
    const car = await carsRepositoryInMemory.create({
      name: "Car1",
      description: "tttt",
      daily_rate: 140,
      license_plate: "DEF-1234",
      fine_amount: 260,
      brand: "Audi",
      category_id: "cat_id",
    });

    const cars = await listAvailableCarsUseCase.execute({});

    expect(cars).toEqual([car]);
  });

  it("should be able to list all available cars by brand", async () => {
    const car = await carsRepositoryInMemory.create({
      name: "Car1",
      description: "tttt",
      daily_rate: 140,
      license_plate: "DEF-1234",
      fine_amount: 260,
      brand: "Fiat",
      category_id: "cat_id",
    });

    const cars = await listAvailableCarsUseCase.execute({ brand: "Fiat" });

    expect(cars).toEqual([car]);
  });

  it("should be able to list all available cars by name", async () => {
    const car = await carsRepositoryInMemory.create({
      name: "Car1",
      description: "tttt",
      daily_rate: 140,
      license_plate: "DEF-1234",
      fine_amount: 260,
      brand: "Fiat",
      category_id: "cat_id",
    });

    const cars = await listAvailableCarsUseCase.execute({ name: "Car1" });

    expect(cars).toEqual([car]);
  });

  it("should be able to list all available cars by category id", async () => {
    const car = await carsRepositoryInMemory.create({
      name: "Car1",
      description: "tttt",
      daily_rate: 140,
      license_plate: "DEF-1234",
      fine_amount: 260,
      brand: "Fiat",
      category_id: "cat_id",
    });

    const cars = await listAvailableCarsUseCase.execute({
      category_id: "cat_id",
    });

    expect(cars).toEqual([car]);
  });
});
